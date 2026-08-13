//! End-to-end proof of Mint's compatible Client Credentials profile.
//!
//! The real router loads a standard-authority registration from disk,
//! authenticates both OAuth client-secret wire methods, mints the same bounded
//! authority for each, rotates and revokes the credential through registry
//! reloads, and keeps raw credentials out of the audit chain.

use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, sync::Arc};

use axum_test::{TestResponse, TestServer};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use registry_mint::{
    config::MintConfig,
    server::{build_app, MintService},
};
use registry_platform_authcommon::fingerprint_api_key;
use registry_platform_crypto::PublicJwk;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};

const ISSUER: &str = "http://127.0.0.1:18182";
const CLIENT_ID: &str = "qgis-installation";
const CLIENT_SECRET: &str = "M7vEwCZZ5R2UjUVn5tQJ8w23F4w7T6s8d9P0yK1mN2o";
const ROTATED_SECRET: &str = "w9B6R7mU3K2zY4V8nX1sA5pC0dE6fG7hJ8kL9qT2uI0";
const RELAY_AUDIENCE: &str = "relay-qgis";
const RELAY_SCOPE: &str = "registry:qgis:premises:read";
const AUDIT_HASH_KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

fn service_key_pair(seed: u8) -> (Value, Value) {
    let scalar = [seed; 32];
    let signing = p256::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-256 scalar");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("uncompressed x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("uncompressed y"));
    let bare = PublicJwk::parse(
        &json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "x":x, "y":y}).to_string(),
    )
    .expect("public JWK parses");
    let kid = bare.jkt().expect("thumbprint computes");
    (
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y}),
        json!({"kty":"EC", "crv":"P-256", "alg":"ES256", "kid":kid, "x":x, "y":y, "d":URL_SAFE_NO_PAD.encode(scalar)}),
    )
}

fn write_owner_only(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write secret file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("restrict secret file");
}

fn write_registration(root: &Path, secrets: &[&str]) {
    let fingerprints = secrets
        .iter()
        .map(|secret| format!("    - {}", fingerprint_api_key(secret)))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(
        root.join("clients/qgis-installation.yaml"),
        format!(
            "clientId: {CLIENT_ID}\nprincipal: urn:example:managed-client:{CLIENT_ID}\nauthorization:\n  scopes: [{RELAY_SCOPE}]\n  claims:\n    purpose: map-consultation\nclientAuthentication:\n  method: client-secret\n  secretFingerprints:\n{fingerprints}\n"
        ),
    )
    .expect("write client registration");
}

struct Deployment {
    _directory: tempfile::TempDir,
    root: std::path::PathBuf,
    service: Arc<MintService>,
}

async fn deployment() -> Deployment {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().to_path_buf();
    fs::create_dir(root.join("secrets")).expect("create secrets directory");
    fs::create_dir(root.join("clients")).expect("create clients directory");
    fs::create_dir(root.join("public-keys")).expect("create public key directory");

    let (signing_public, signing_private) = service_key_pair(11);
    let public_file = format!(
        "{}.jwk.json",
        signing_public["kid"].as_str().expect("service key id")
    );
    fs::write(
        root.join("public-keys").join(&public_file),
        signing_public.to_string(),
    )
    .expect("write public key");
    write_owner_only(
        &root.join("secrets/signing.jwk"),
        signing_private.to_string().as_bytes(),
    );
    write_owner_only(&root.join("secrets/audit-hmac-key"), AUDIT_HASH_KEY);
    write_registration(&root, &[CLIENT_SECRET]);

    let config_path = root.join("mint.yaml");
    fs::write(
        &config_path,
        format!(
            r#"
version: 1
validationMode: supervised-local-development
issuer: {ISSUER}
listener: {{address: 127.0.0.1, port: 18182}}
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
  audiences: [{RELAY_AUDIENCE}]
  lifetimeSeconds: 60
clientAssertion:
  audience: {ISSUER}/token
  algorithms: [EdDSA]
clients:
  directory: clients
"#,
            root.join("secrets").display()
        ),
    )
    .expect("write Mint configuration");

    let config = MintConfig::load(&config_path).expect("configuration loads");
    let service = Arc::new(MintService::load(config).await.expect("service loads"));
    Deployment {
        _directory: directory,
        root,
        service,
    }
}

fn basic_header(client_id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{client_id}:{secret}")))
}

async fn request_basic(http: &TestServer, client_id: &str, secret: &str) -> TestResponse {
    http.post("/token")
        .add_header("authorization", basic_header(client_id, secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "caller:cannot:widen"),
        ])
        .await
}

fn verifier(jwks: &Value) -> TokenVerifier {
    let key_set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(jwks.clone()).expect("published keys parse");
    TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            ISSUER.to_owned(),
            vec![RELAY_AUDIENCE.to_owned()],
            vec![jsonwebtoken::Algorithm::ES256],
            vec!["at+jwt".to_owned()],
        ),
        Arc::new(JwksFetcher::new_static(
            key_set,
            JwksFetcherConfig::defaults(),
        )),
    )
}

#[tokio::test]
async fn standard_clients_reacquire_fixed_authority_with_basic_or_post() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let published = http.get("/.well-known/jwks.json").await.json::<Value>();
    let verifier = verifier(&published);

    let basic = request_basic(&http, CLIENT_ID, CLIENT_SECRET).await;
    basic.assert_status_ok();
    assert_eq!(basic.header("cache-control"), "no-store");
    let basic_body = basic.json::<Value>();
    assert_eq!(basic_body["token_type"], json!("Bearer"));
    assert_eq!(basic_body["expires_in"], json!(60));
    assert_eq!(basic_body["scope"], json!(RELAY_SCOPE));
    assert!(basic_body.get("refresh_token").is_none());

    let post = http
        .post("/token")
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("scope", "caller:cannot:widen"),
        ])
        .await;
    post.assert_status_ok();
    let post_body = post.json::<Value>();
    assert_eq!(post_body["scope"], json!(RELAY_SCOPE));
    assert_ne!(post_body["access_token"], basic_body["access_token"]);

    for body in [&basic_body, &post_body] {
        let token = body["access_token"].as_str().expect("access token");
        let verified = verifier.verify(token).await.expect("token verifies");
        assert_eq!(
            verified.claims.sub.as_deref(),
            Some("urn:example:managed-client:qgis-installation")
        );
        assert_eq!(verified.claims.client_id.as_deref(), Some(CLIENT_ID));
        assert_eq!(verified.scopes, [RELAY_SCOPE]);
        assert_eq!(verified.claims.extra["purpose"], json!("map-consultation"));
    }

    let metadata = http
        .get("/.well-known/oauth-authorization-server")
        .await
        .json::<Value>();
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!([
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post"
        ])
    );

    let wrong = request_basic(&http, CLIENT_ID, "wrong-secret").await;
    let unknown = request_basic(&http, "unknown-installation", CLIENT_SECRET).await;
    wrong.assert_status_unauthorized();
    unknown.assert_status_unauthorized();
    assert_eq!(wrong.json::<Value>(), json!({"error": "invalid_client"}));
    assert_eq!(unknown.json::<Value>(), json!({"error": "invalid_client"}));
    assert_eq!(
        wrong.header("www-authenticate").to_str().expect("header"),
        "Basic realm=\"registry-mint\""
    );

    let audit =
        fs::read_to_string(deployment.root.join("audit/mint.jsonl")).expect("audit chain reads");
    for sensitive in [CLIENT_ID, CLIENT_SECRET, ROTATED_SECRET] {
        assert!(
            !audit.contains(sensitive),
            "audit exposed client credential material"
        );
    }
}

#[tokio::test]
async fn rotation_and_reload_revoke_only_future_token_requests() {
    let deployment = deployment().await;
    let http = TestServer::new(build_app(Arc::clone(&deployment.service)));
    let published = http.get("/.well-known/jwks.json").await.json::<Value>();
    let verifier = verifier(&published);

    let issued = request_basic(&http, CLIENT_ID, CLIENT_SECRET).await;
    issued.assert_status_ok();
    let retained = issued.json::<Value>()["access_token"]
        .as_str()
        .expect("access token")
        .to_owned();

    write_registration(&deployment.root, &[CLIENT_SECRET, ROTATED_SECRET]);
    assert_eq!(
        deployment
            .service
            .reload_clients()
            .expect("rotation reloads"),
        1
    );
    request_basic(&http, CLIENT_ID, CLIENT_SECRET)
        .await
        .assert_status_ok();
    request_basic(&http, CLIENT_ID, ROTATED_SECRET)
        .await
        .assert_status_ok();

    write_registration(&deployment.root, &[ROTATED_SECRET]);
    assert_eq!(
        deployment
            .service
            .reload_clients()
            .expect("removal reloads"),
        1
    );
    request_basic(&http, CLIENT_ID, CLIENT_SECRET)
        .await
        .assert_status_unauthorized();
    request_basic(&http, CLIENT_ID, ROTATED_SECRET)
        .await
        .assert_status_ok();

    fs::remove_file(deployment.root.join("clients/qgis-installation.yaml"))
        .expect("remove registration");
    assert_eq!(
        deployment
            .service
            .reload_clients()
            .expect("revocation reloads"),
        0
    );
    request_basic(&http, CLIENT_ID, ROTATED_SECRET)
        .await
        .assert_status_unauthorized();

    verifier
        .verify(&retained)
        .await
        .expect("a previously issued token remains valid only until its expiry");
}
