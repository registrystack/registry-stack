//! End-to-end proof that the offer boundary is a resource server for tokens
//! Mint really issued.
//!
//! The adopter-facing offer endpoint is the only authorization boundary this
//! service has, so its verification profile is not something to assert against
//! a token this test wrote itself. The deployment below is a real Mint on disk,
//! driven through its real router, and the token handed to the resource server
//! is the one Mint minted. Only the key source is substituted, for the same
//! reason Mint's own compatibility test substitutes it: the key set is the one
//! Mint published, read directly rather than over a network fetch.
//!
//! Nothing here touches the client half of the process. This service's own Mint
//! client identity has no part in any decision below, which is the separation
//! [`registry_evidence_oid4vci::authorizer`] exists to keep.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence_oid4vci::{
    authorizer::{verifier_profile, AuthorizationError, MintResourceServer, OfferAuthorizer},
    config::{AccessTokenAlgorithm, OfferAuthorizationConfig},
};
use registry_mint::{
    config::MintConfig,
    server::{build_app, MintService},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS,
};
use registry_platform_crypto::{sign, PrivateJwk, PublicJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use serde_json::{json, Value};

/// A fixed, non-secret audit HMAC key. Held as a byte literal rather than
/// written inline so a secret scanner does not read the write call as an
/// assignment of a live credential.
const AUDIT_HASH_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const ISSUER: &str = "http://127.0.0.1:18091";
const ASSERTION_AUDIENCE: &str = "http://127.0.0.1:18091/token";
const OFFER_AUDIENCE: &str = "https://delivery.example.org";
const CLIENT_ID: &str = "offer-caller";
const PRINCIPAL: &str = "urn:example:offer-caller";

/// Deterministic Ed25519 material for the client registration.
fn client_key_pair(seed: u8) -> (PrivateJwk, Value) {
    let seed_bytes = [seed; 32];
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
    let d = URL_SAFE_NO_PAD.encode(seed_bytes);
    let kid = format!("client-key-{seed}");
    let public = json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x});
    let private = PrivateJwk::parse(
        &json!({"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "x": x, "d": d})
            .to_string(),
    )
    .expect("the private JWK parses");
    (private, public)
}

/// Deterministic P-256 material for the token signing key, so the access token
/// this test verifies is ES256 signed exactly as a deployment's would be.
fn signing_key_pair(seed: u8) -> (Value, Value) {
    let scalar = [seed; 32];
    let signing = p256::ecdsa::SigningKey::from_slice(&scalar).expect("a valid P-256 scalar");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("an uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("an uncompressed point has y"));
    let bare = PublicJwk::parse(
        &json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "x": x, "y": y}).to_string(),
    )
    .expect("the public JWK parses");
    let kid = bare.jkt().expect("the thumbprint computes");
    (
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "x": x, "y": y}),
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "x": x, "y": y,
               "d": URL_SAFE_NO_PAD.encode(scalar)}),
    )
}

struct Deployment {
    /// Held so the directory outlives the service that reads from it.
    _directory: tempfile::TempDir,
    service: Arc<MintService>,
}

/// Write a complete Mint deployment to disk and load it exactly as the binary
/// would, including the owner-only permission requirement on the signing key.
async fn deployment() -> Deployment {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path();
    for child in ["secrets", "clients", "public-keys"] {
        fs::create_dir(root.join(child)).expect("create a deployment directory");
    }

    let (signing_public, signing_document) = signing_key_pair(7);
    let public_file = format!(
        "{}.jwk.json",
        signing_public["kid"].as_str().expect("the key has an id")
    );
    fs::write(
        root.join("public-keys").join(&public_file),
        signing_public.to_string(),
    )
    .expect("write the published public key");
    write_owner_only(
        &root.join("secrets/signing.jwk"),
        signing_document.to_string().as_bytes(),
    );
    write_owner_only(&root.join("secrets/audit-hmac-key"), AUDIT_HASH_KEY);

    let (_, client_public) = client_key_pair(3);
    fs::write(
        root.join(format!("clients/{CLIENT_ID}.yaml")),
        format!(
            "clientId: {CLIENT_ID}\nprincipal: {PRINCIPAL}\nevidenceAudience: {OFFER_AUDIENCE}\nrequesterTags: [{CLIENT_ID}]\nkeys: [{client_public}]\n"
        ),
    )
    .expect("write the client registration");

    let config_path = root.join("mint.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
version: 1
validationMode: supervised-local-development
issuer: {ISSUER}
listener: {{address: 127.0.0.1, port: 18091}}
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/{public_file}
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing.jwk
secretProviders:
  file: {{root: {}}}
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [{OFFER_AUDIENCE}]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
clientAssertion:
  audience: {ASSERTION_AUDIENCE}
  algorithms: [EdDSA]
clients:
  directory: clients
"#,
            root.join("secrets").display()
        ),
    )
    .expect("write the deployment configuration");

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

fn write_owner_only(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write a deployment secret");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("restrict a deployment secret");
}

fn sign_assertion(private: &PrivateJwk, claims: &Value) -> String {
    let kid = private.kid.clone().expect("the test key has an id");
    let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
    let encode = |value: &Value| {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("value serializes"))
    };
    let signing_input = format!("{}.{}", encode(&header), encode(claims));
    let signature = sign(signing_input.as_bytes(), private).expect("the key signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Drive the real Mint router and return the token it issued together with the
/// key set it published.
async fn minted_offer_token() -> (String, Value) {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));

    let published = http.get("/.well-known/jwks.json").await;
    published.assert_status_ok();
    let key_set = published.json::<Value>();

    let (private, _) = client_key_pair(3);
    let now = chrono::Utc::now().timestamp();
    let assertion = sign_assertion(
        &private,
        &json!({
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": ASSERTION_AUDIENCE,
            "iat": now,
            "exp": now + 120,
            "jti": "offer-authorization-1",
        }),
    );
    let response = http
        .post("/token")
        .form(&vec![
            (
                "grant_type".to_owned(),
                GRANT_TYPE_CLIENT_CREDENTIALS.to_owned(),
            ),
            (
                "client_assertion_type".to_owned(),
                CLIENT_ASSERTION_TYPE.to_owned(),
            ),
            ("client_assertion".to_owned(), assertion),
        ])
        .await;
    response.assert_status_ok();
    let token = response.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned();
    (token, key_set)
}

/// The offer boundary, built over the profile the deployment configuration
/// states and over the key set Mint published.
fn resource_server(config: &OfferAuthorizationConfig, key_set: &Value) -> MintResourceServer {
    let parsed: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(key_set.clone()).expect("Mint publishes a parsable key set");
    let fetcher = Arc::new(JwksFetcher::new_static(
        parsed,
        JwksFetcherConfig::defaults(),
    ));
    MintResourceServer::new(Arc::new(TokenVerifier::new(
        verifier_profile(config),
        fetcher,
    )))
}

fn offer_config(audience: &str) -> OfferAuthorizationConfig {
    OfferAuthorizationConfig {
        issuer: ISSUER.to_owned(),
        jwks_uri: format!("{ISSUER}/.well-known/jwks.json"),
        audiences: vec![audience.to_owned()],
        algorithms: vec![AccessTokenAlgorithm::ES256],
        authorized_clients: Vec::new(),
        maximum_token_lifetime_seconds: 900,
    }
}

#[tokio::test]
async fn a_token_mint_issued_authorizes_an_offer() {
    let (token, key_set) = minted_offer_token().await;
    let authorized = resource_server(&offer_config(OFFER_AUDIENCE), &key_set)
        .authorize(&token)
        .await
        .expect("the offer boundary accepts a token Mint issued");

    // Both come from the server-side registration Mint holds, never from
    // anything the caller asserted.
    assert_eq!(authorized.client.as_deref(), Some(CLIENT_ID));
    assert_eq!(authorized.subject.as_deref(), Some(PRINCIPAL));
}

#[tokio::test]
async fn a_token_mint_issued_for_another_resource_server_is_refused() {
    let (token, key_set) = minted_offer_token().await;
    // The same real token, presented to a deployment that answers to a
    // different audience. An adopter's token for another resource server is
    // not an offer authorization here.
    assert_eq!(
        resource_server(&offer_config("https://elsewhere.example.org"), &key_set)
            .authorize(&token)
            .await,
        Err(AuthorizationError::Refused)
    );
}

#[tokio::test]
async fn a_token_this_issuer_did_not_sign_is_refused() {
    let (token, key_set) = minted_offer_token().await;
    let config = offer_config(OFFER_AUDIENCE);
    let server = resource_server(&config, &key_set);

    // A token whose signature was replaced, presented otherwise unchanged.
    let mut parts: Vec<&str> = token.split('.').collect();
    parts.pop();
    let forged = format!("{}.{}", parts.join("."), URL_SAFE_NO_PAD.encode([0_u8; 64]));
    assert_eq!(
        server.authorize(&forged).await,
        Err(AuthorizationError::Refused)
    );
    assert_eq!(
        server.authorize("not-a-token").await,
        Err(AuthorizationError::Refused)
    );
    assert_eq!(server.authorize("").await, Err(AuthorizationError::Missing));
}
