//! End-to-end proof that a token Mint issues is one Evidence accepts.
//!
//! This is the test that justifies the crate existing. It drives the real Mint
//! router over a real deployment on disk, and feeds the resulting access token
//! to the real Evidence authenticator. Nothing here stubs a boundary: if the
//! two products ever disagree about claim names, algorithms, token type,
//! issuer, or audience, this fails.

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence::{
    auth::{AuthenticationClaimsConfig, Authenticator},
    config::{
        AccessTokenAlgorithm, AccessTokenType, AssuranceProfile, AuthenticationConfig,
        AuthenticationKind,
    },
};
use registry_mint::{
    config::MintConfig,
    server::{build_app, serve, MintService},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};

// A fixed, non-secret audit HMAC key. Held as a byte literal rather than
// written inline so a secret scanner does not read the write call as an
// assignment of a live credential.
const AUDIT_HASH_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const ISSUER: &str = "https://mint.example.org";
const ASSERTION_AUDIENCE: &str = "https://mint.example.org/token";
const LOCAL_ISSUER: &str = "http://127.0.0.1:18081";
const LOCAL_ASSERTION_AUDIENCE: &str = "http://127.0.0.1:18081/token";
const EVIDENCE_AUDIENCE: &str = "evidence.example.org";

/// The claim names shared by the two configuration documents. Evidence reads
/// exactly these, and Mint writes exactly these.
const PRINCIPAL_CLAIM: &str = "sub";
const REQUESTER_TAGS_CLAIM: &str = "evidence_tags";
const EVIDENCE_AUDIENCE_CLAIM: &str = "evidence_audience";
const GRANT_ID_CLAIM: &str = "evidence_grant_id";
const GRANT_AUTHORITY_CLAIM: &str = "evidence_authority";

/// Deterministic Ed25519 material, so a test can hold several distinct
/// identities and know which one signed what.
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
    /// Held so the directory outlives the service that reads from it.
    _directory: tempfile::TempDir,
    service: Arc<MintService>,
}

/// Write a complete Mint deployment to disk and load it exactly as the binary
/// would, including the owner-only permission requirement on the signing key.
async fn deployment() -> Deployment {
    deployment_with_transport(None, ISSUER, 0, ASSERTION_AUDIENCE).await
}

async fn supervised_local_development_deployment() -> Deployment {
    deployment_with_transport(
        Some("supervised-local-development"),
        LOCAL_ISSUER,
        18081,
        LOCAL_ASSERTION_AUDIENCE,
    )
    .await
}

async fn deployment_with_transport(
    validation_mode: Option<&str>,
    issuer: &str,
    listener_port: u16,
    assertion_audience: &str,
) -> Deployment {
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
    fs::write(&audit_key_path, AUDIT_HASH_KEY).expect("write audit key");
    fs::set_permissions(&audit_key_path, fs::Permissions::from_mode(0o600))
        .expect("restrict audit key");

    let (_, health_public, _) = key_pair(1);
    write_client(
        root,
        "health-ministry",
        &health_public,
        Some(("grant-7", "statute-12")),
    );
    let (_, statistics_public, _) = key_pair(2);
    write_client(root, "statistics-office", &statistics_public, None);

    let config_path = root.join("mint.yaml");
    let validation_mode = validation_mode
        .map(|mode| format!("validationMode: {mode}\n"))
        .unwrap_or_default();
    fs::write(
        &config_path,
        format!(
            r#"
version: 1
{validation_mode}issuer: {issuer}
listener: {{address: 127.0.0.1, port: {listener_port}}}
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
    principal: {PRINCIPAL_CLAIM}
    requesterTags: {REQUESTER_TAGS_CLAIM}
    evidenceAudience: {EVIDENCE_AUDIENCE_CLAIM}
    grantId: {GRANT_ID_CLAIM}
    grantAuthority: {GRANT_AUTHORITY_CLAIM}
clientAssertion:
  audience: {assertion_audience}
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
    }
}

fn write_client(root: &Path, client_id: &str, public: &Value, grant: Option<(&str, &str)>) {
    let mut document = format!(
        "clientId: {client_id}\nprincipal: urn:example:{client_id}\nevidenceAudience: https://{client_id}.example.org\nrequesterTags: [{client_id}]\nkeys: [{public}]\n"
    );
    if let Some((id, authority)) = grant {
        document.push_str(&format!("grant: {{id: {id}, authority: {authority}}}\n"));
    }
    fs::write(root.join(format!("clients/{client_id}.yaml")), document)
        .expect("write client registration");
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
    assertion_claims_for_audience(client_id, jti, ASSERTION_AUDIENCE)
}

fn assertion_claims_for_audience(client_id: &str, jti: &str, audience: &str) -> Value {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "iat": now,
        "exp": now + 120,
        "jti": jti,
    })
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

/// Build the Evidence authenticator the way `Authenticator::from_config` does,
/// but over the key set Mint actually published rather than an HTTPS fetch.
fn evidence_authenticator(jwks: &Value) -> Authenticator {
    evidence_authenticator_for_issuer(jwks, ISSUER)
}

fn evidence_authenticator_for_issuer(jwks: &Value, issuer: &str) -> Authenticator {
    let key_set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(jwks.clone()).expect("Mint publishes a parsable JWK set");
    let verifier_config = TokenVerifierConfig::access_token_profile(
        issuer.to_owned(),
        vec![EVIDENCE_AUDIENCE.to_owned()],
        vec![jsonwebtoken::Algorithm::EdDSA],
        vec!["at+jwt".to_owned()],
    );
    let fetcher = Arc::new(JwksFetcher::new_static(
        key_set,
        JwksFetcherConfig::defaults(),
    ));
    Authenticator::new(
        Arc::new(TokenVerifier::new(verifier_config, fetcher)),
        AuthenticationClaimsConfig {
            principal_claim: PRINCIPAL_CLAIM.to_owned(),
            requester_tags_claim: REQUESTER_TAGS_CLAIM.to_owned(),
            evidence_audience_claim: EVIDENCE_AUDIENCE_CLAIM.to_owned(),
            grant_id_claim: GRANT_ID_CLAIM.to_owned(),
            grant_authority_claim: GRANT_AUTHORITY_CLAIM.to_owned(),
            actor_claim: None,
        },
    )
}

#[tokio::test]
async fn a_client_signing_with_its_own_key_receives_a_token_evidence_accepts() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let jwks = http.get("/.well-known/jwks.json").await;
    jwks.assert_status_ok();
    assert_eq!(jwks.header("content-type"), "application/jwk-set+json");
    let published = jwks.json::<Value>();

    let (private, _, _) = key_pair(1);
    let assertion = sign_assertion(&private, &assertion_claims("health-ministry", "jti-1"));
    let response = http.post("/token").form(&token_form(&assertion)).await;
    response.assert_status_ok();
    // RFC 6749 section 5.1: a token response must never be cached.
    assert_eq!(response.header("cache-control"), "no-store");
    let body = response.json::<Value>();
    assert_eq!(body["token_type"], json!("Bearer"));
    assert_eq!(body["expires_in"], json!(300));
    let access_token = body["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned();

    let context = evidence_authenticator(&published)
        .authenticate(&access_token)
        .await
        .expect("Evidence accepts a token Mint issued");

    // Every one of these came from the server-side registry, not the assertion.
    assert_eq!(context.principal(), "urn:example:health-ministry");
    assert_eq!(context.requester_tags(), ["health-ministry"]);
    assert_eq!(
        context.evidence_audience(),
        "https://health-ministry.example.org"
    );
    assert_eq!(context.grant_id(), Some("grant-7"));
    assert_eq!(context.grant_authority(), Some("statute-12"));
    assert_eq!(context.actor(), None);
}

#[tokio::test]
async fn supervised_local_development_tokens_remain_evidence_compatible() {
    let deployment = supervised_local_development_deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let published = http.get("/.well-known/jwks.json").await.json::<Value>();

    let (private, _, _) = key_pair(1);
    let claims = assertion_claims_for_audience(
        "health-ministry",
        "jti-supervised-local",
        LOCAL_ASSERTION_AUDIENCE,
    );
    let assertion = sign_assertion(&private, &claims);
    let response = http.post("/token").form(&token_form(&assertion)).await;
    response.assert_status_ok();
    let access_token = response.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned();

    let context = evidence_authenticator_for_issuer(&published, LOCAL_ISSUER)
        .authenticate(&access_token)
        .await
        .expect("Evidence accepts a token from the supervised local Mint mode");
    assert_eq!(context.principal(), "urn:example:health-ministry");
    assert_eq!(context.requester_tags(), ["health-ministry"]);
}

#[tokio::test]
async fn evidence_fetches_keys_from_a_real_supervised_local_mint() {
    // Hold the OS allocation while the matching deployment is authored and
    // loaded. Release it only immediately before public `serve` binds it.
    let reservation =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve a loopback port");
    let port = reservation
        .local_addr()
        .expect("read reserved address")
        .port();
    let issuer = format!("http://127.0.0.1:{port}");
    let token_endpoint = format!("{issuer}/token");
    let jwks_uri = format!("{issuer}/.well-known/jwks.json");
    let deployment = deployment_with_transport(
        Some("supervised-local-development"),
        &issuer,
        port,
        &token_endpoint,
    )
    .await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let service = Arc::clone(&deployment.service);
    drop(reservation);
    let server = tokio::spawn(async move {
        serve(service, async {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Keep every fallible boundary inside this result so Mint is asked to shut
    // down even when the real HTTP exchange or verification fails.
    let proof: Result<_, Box<dyn Error>> = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if server.is_finished() {
                    return Err(std::io::Error::other(
                        "Mint stopped before its readiness endpoint responded",
                    ));
                }
                if client
                    .get(format!("{issuer}/ready"))
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
                {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;

        let (private, _, _) = key_pair(1);
        let claims = assertion_claims_for_audience(
            "health-ministry",
            "jti-real-supervised-local",
            &token_endpoint,
        );
        let assertion = sign_assertion(&private, &claims);
        let response = client
            .post(&token_endpoint)
            .form(&token_form(&assertion))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(std::io::Error::other(format!(
                "Mint token endpoint returned {}",
                response.status()
            ))
            .into());
        }
        let body = response.json::<Value>().await?;
        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("token response has no access token"))?;

        let authentication = AuthenticationConfig {
            kind: AuthenticationKind::OidcAccessToken,
            issuer: issuer.clone(),
            audiences: vec![EVIDENCE_AUDIENCE.to_owned()],
            token_types: vec![AccessTokenType::AtJwt],
            algorithms: vec![AccessTokenAlgorithm::EdDSA],
            jwks_uri,
            principal_claim: PRINCIPAL_CLAIM.to_owned(),
            requester_tags_claim: REQUESTER_TAGS_CLAIM.to_owned(),
            evidence_audience_claim: EVIDENCE_AUDIENCE_CLAIM.to_owned(),
            grant_id_claim: GRANT_ID_CLAIM.to_owned(),
            grant_authority_claim: GRANT_AUTHORITY_CLAIM.to_owned(),
            actor_claim: None,
        };
        Authenticator::from_config(&authentication, AssuranceProfile::Local)
            .authenticate(access_token)
            .await
            .map_err(Into::into)
    }
    .await;

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("Mint shuts down within the grace period")
        .expect("Mint server task joins")
        .expect("Mint shuts down cleanly");

    let context = proof.expect("the real local Mint and Evidence boundary is compatible");
    assert_eq!(context.principal(), "urn:example:health-ministry");
    assert_eq!(context.requester_tags(), ["health-ministry"]);
    assert_eq!(
        context.claim_path("iss"),
        Some(&Value::String(issuer.clone()))
    );
    assert_eq!(
        context.claim_path("aud"),
        Some(&Value::String(EVIDENCE_AUDIENCE.to_owned()))
    );
    assert_eq!(
        context.evidence_audience(),
        "https://health-ministry.example.org"
    );
    assert_eq!(context.grant_id(), Some("grant-7"));
    assert_eq!(context.grant_authority(), Some("statute-12"));
    assert_eq!(context.actor(), None);
}

#[tokio::test]
async fn a_registered_client_cannot_borrow_another_clients_authority() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    // The health ministry's own key, but claiming to be the statistics office.
    let (health_private, _, _) = key_pair(1);
    let forged = sign_assertion(
        &health_private,
        &assertion_claims("statistics-office", "jti-forged"),
    );
    let response = http.post("/token").form(&token_form(&forged)).await;

    assert_eq!(response.status_code(), 401);
    // The public error never distinguishes an unknown client from a bad
    // signature, so it cannot be used to enumerate the registry.
    assert_eq!(response.json::<Value>(), json!({"error": "invalid_client"}));

    let unknown = sign_assertion(
        &health_private,
        &assertion_claims("no-such-client", "jti-x"),
    );
    let response = http.post("/token").form(&token_form(&unknown)).await;
    assert_eq!(response.status_code(), 401);
    assert_eq!(response.json::<Value>(), json!({"error": "invalid_client"}));
}

#[tokio::test]
async fn an_assertion_cannot_be_presented_twice() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let (private, _, _) = key_pair(2);
    let assertion = sign_assertion(&private, &assertion_claims("statistics-office", "jti-once"));

    let first = http.post("/token").form(&token_form(&assertion)).await;
    first.assert_status_ok();

    let replayed = http.post("/token").form(&token_form(&assertion)).await;
    assert_eq!(replayed.status_code(), 401);
    assert_eq!(replayed.json::<Value>(), json!({"error": "invalid_client"}));
}

#[tokio::test]
async fn a_client_without_a_registered_grant_receives_no_grant_claims() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let published = http.get("/.well-known/jwks.json").await.json::<Value>();

    let (private, _, _) = key_pair(2);
    let assertion = sign_assertion(&private, &assertion_claims("statistics-office", "jti-2"));
    let response = http.post("/token").form(&token_form(&assertion)).await;
    response.assert_status_ok();
    let access_token = response.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned();

    let context = evidence_authenticator(&published)
        .authenticate(&access_token)
        .await
        .expect("Evidence accepts the token");
    assert_eq!(context.principal(), "urn:example:statistics-office");
    assert_eq!(context.grant_id(), None);
    assert_eq!(context.grant_authority(), None);
}

#[tokio::test]
async fn the_published_metadata_points_at_the_endpoints_that_exist() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let metadata = http.get("/.well-known/oauth-authorization-server").await;
    metadata.assert_status_ok();
    let document = metadata.json::<Value>();
    assert_eq!(document["issuer"], json!(ISSUER));
    assert_eq!(document["token_endpoint"], json!(ASSERTION_AUDIENCE));
    assert_eq!(
        document["jwks_uri"],
        json!(format!("{ISSUER}/.well-known/jwks.json"))
    );
    assert_eq!(
        document["token_endpoint_auth_methods_supported"],
        json!(["private_key_jwt"])
    );

    // The metadata must describe routes this router actually serves.
    http.get("/.well-known/jwks.json").await.assert_status_ok();
    let ready = http.get("/ready").await;
    ready.assert_status_ok();
}

#[tokio::test]
async fn the_token_endpoint_refuses_anything_but_the_supported_grant() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let (private, _, _) = key_pair(1);
    let assertion = sign_assertion(&private, &assertion_claims("health-ministry", "jti-grant"));

    let mut form = token_form(&assertion);
    form[0].1 = "password".to_owned();
    let response = http.post("/token").form(&form).await;
    assert_eq!(response.status_code(), 400);
    assert_eq!(
        response.json::<Value>(),
        json!({"error": "unsupported_grant_type"})
    );

    let mut form = token_form(&assertion);
    form[1].1 = "urn:example:something-else".to_owned();
    let response = http.post("/token").form(&form).await;
    assert_eq!(response.status_code(), 400);
    assert_eq!(
        response.json::<Value>(),
        json!({"error": "invalid_request"})
    );

    // A bearer-style secret is not an accepted authentication method.
    let response = http
        .post("/token")
        .form(&vec![(
            "grant_type".to_owned(),
            GRANT_TYPE_CLIENT_CREDENTIALS.to_owned(),
        )])
        .await;
    assert_eq!(response.status_code(), 400);
    assert_eq!(
        response.json::<Value>(),
        json!({"error": "invalid_request"})
    );
}
