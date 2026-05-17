// SPDX-License-Identifier: Apache-2.0
//! End-to-end integration coverage for the OIDC bearer-JWT verifier
//! against a real Zitadel instance.
//!
//! The publicschema.com dev Compose stack provisions a Zitadel
//! organisation, project, OIDC web application, test human user, and
//! machine service account on first boot, then writes the credentials
//! to `compose/seed/zitadel.env`. See
//! `apps/publicschema.com/compose/seed/zitadel-bootstrap.md` for the
//! exact resources created and the env-file shape.
//!
//! ## Running
//!
//! Marked `#[ignore]` because it requires a running Zitadel and is not
//! safe to run on every `cargo test` invocation. Explicit:
//!
//! ```bash
//! source ../publicschema.com/compose/seed/zitadel.env
//! cargo test --test oidc_zitadel -- --ignored --nocapture
//! ```
//!
//! Required env vars (matching the bootstrap output):
//!
//! * `OIDC_ISSUER`         issuer URL, e.g. `http://localhost:8080`
//! * `OIDC_CLIENT_ID`      Zitadel OIDC app `clientId`
//! * `OIDC_CLIENT_SECRET`  Zitadel OIDC app `clientSecret`
//!
//! The test prerequisites the OIDC application to have the
//! `client_credentials` grant enabled. The default bootstrap creates
//! the app with `AUTHORIZATION_CODE + REFRESH_TOKEN` only, so this
//! grant must be enabled either by editing the bootstrap script or by
//! toggling it in the Zitadel console (`Applications` → the app →
//! `Grant types`).
//!
//! ## What is asserted
//!
//! * Happy path: a freshly minted bearer JWT is accepted, `Principal`
//!   is populated, `auth_mode=oidc`.
//! * `auth.token_signature_invalid` when the signature segment is
//!   tampered.
//! * `auth.audience_mismatch` when the verifier is configured with an
//!   audience the IdP did not include.
//! * `auth.issuer_mismatch` when the verifier is configured with the
//!   wrong issuer (but still points at the real JWKS).
//! * `auth.missing_credential` when no Authorization header is sent.

use std::collections::BTreeMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_relay::auth::middleware::auth_layer;
use registry_relay::auth::oidc::{OidcAuth, ReqwestJwksFetcher};
use registry_relay::auth::{AuthMode, Principal};
use registry_relay::config::{OidcAlgorithm, OidcConfig};
use serde_json::Value;
use tower::ServiceExt;

/// Returns `Ok` only when all three Zitadel env vars are present.
/// Otherwise returns the human-readable reason for skipping; callers
/// `eprintln!` and `return` to keep the test as a no-op skip.
fn zitadel_env() -> Result<ZitadelEnv, String> {
    let issuer = env::var("OIDC_ISSUER").map_err(|_| "OIDC_ISSUER not set".to_string())?;
    let client_id = env::var("OIDC_CLIENT_ID").map_err(|_| "OIDC_CLIENT_ID not set".to_string())?;
    let client_secret =
        env::var("OIDC_CLIENT_SECRET").map_err(|_| "OIDC_CLIENT_SECRET not set".to_string())?;
    if issuer.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return Err(
            "one or more of OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET is empty".to_string(),
        );
    }
    Ok(ZitadelEnv {
        issuer,
        client_id,
        client_secret,
    })
}

struct ZitadelEnv {
    issuer: String,
    client_id: String,
    client_secret: String,
}

impl ZitadelEnv {
    fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }
}

/// Mint a bearer JWT against Zitadel via the OAuth2 client_credentials
/// grant. The request is form-encoded with Basic auth; Zitadel returns
/// a JSON envelope with `access_token`, `token_type`, etc.
async fn mint_zitadel_token(env: &ZitadelEnv) -> String {
    let token_url = format!("{}/oauth/v2/token", env.issuer);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client builds");
    let resp = client
        .post(&token_url)
        .basic_auth(&env.client_id, Some(&env.client_secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", "openid profile"),
        ])
        .send()
        .await
        .expect("zitadel token endpoint reachable");
    let status = resp.status();
    let body = resp
        .text()
        .await
        .expect("zitadel token endpoint response body");
    assert!(
        status.is_success(),
        "zitadel token endpoint returned {status}: {body}.\n\
         The OIDC application probably does not have the `client_credentials` grant enabled. \
         Enable it via the Zitadel console (Applications → grant types) and re-run."
    );
    let payload: Value = serde_json::from_str(&body).expect("zitadel response is JSON");
    payload
        .get("access_token")
        .and_then(Value::as_str)
        .expect("access_token in zitadel response")
        .to_string()
}

/// Decode (without verification) the payload segment of a JWT so we
/// can read its `aud` and `sub` claims and configure the verifier
/// without baking the project id into the test.
fn decode_jwt_payload(token: &str) -> Value {
    let segment = token.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .expect("jwt payload is base64url");
    serde_json::from_slice(&bytes).expect("jwt payload is JSON")
}

/// Project a JWT `aud` claim (string or array) into a Vec<String>.
fn audience_from_payload(payload: &Value) -> Vec<String> {
    match payload.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// Build an [`OidcConfig`] pointing at the live Zitadel discovery URL
/// with the audience extracted from a minted token.
fn oidc_config(env: &ZitadelEnv, audience: Vec<String>) -> OidcConfig {
    OidcConfig {
        issuer: env.issuer.clone(),
        audience,
        jwks_url: None,
        discovery_url: Some(env.discovery_url()),
        algorithms: vec![
            OidcAlgorithm::Rs256,
            OidcAlgorithm::Es256,
            OidcAlgorithm::EdDsa,
        ],
        jwks_cache_ttl: Duration::from_secs(60),
        leeway: Duration::from_secs(60),
        scope_claim: "scope".to_string(),
        scope_map: BTreeMap::new(),
        allowed_clients: Vec::new(),
        token_types: vec!["JWT".to_string(), "at+jwt".to_string()],
    }
}

/// Build a live [`OidcAuth`] from a config block. Resolves the JWKS
/// URL via Zitadel's OIDC discovery document.
async fn build_provider(cfg: &OidcConfig) -> Arc<OidcAuth> {
    let discovery_url = cfg
        .discovery_url
        .as_deref()
        .expect("discovery_url is set in test config");
    let fetcher = ReqwestJwksFetcher::from_discovery_url(discovery_url, &cfg.issuer)
        .await
        .expect("discovery resolves");
    Arc::new(OidcAuth::new(cfg, Arc::new(fetcher)))
}

/// Build a router with the auth layer in front of a tiny `/whoami`
/// handler that returns the request's [`Principal`] as JSON.
fn router_with_provider(provider: Arc<OidcAuth>) -> Router {
    auth_layer(
        Router::new().route("/whoami", get(whoami_handler)),
        provider,
    )
}

async fn whoami_handler(Extension(principal): Extension<Principal>) -> impl IntoResponse {
    let scopes: Vec<&str> = principal.scopes.iter().collect();
    let mode = match principal.auth_mode {
        AuthMode::ApiKey => "api_key",
        AuthMode::Oidc => "oidc",
    };
    axum::Json(serde_json::json!({
        "principal_id": principal.principal_id,
        "scopes": scopes,
        "auth_mode": mode,
    }))
}

/// Tamper with the last byte of the signature segment so the JWT
/// fails signature verification but stays structurally valid.
fn tamper_signature(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have three segments");
    let mut sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("signature segment is base64url");
    let last = sig.last_mut().expect("signature has at least one byte");
    *last ^= 0xff;
    let tampered = URL_SAFE_NO_PAD.encode(&sig);
    format!("{}.{}.{}", parts[0], parts[1], tampered)
}

/// Send a request through the router with the given Authorization
/// header value and return the parsed Problem Details body plus the
/// HTTP status.
async fn send_request(router: Router, auth_header: Option<&str>) -> (StatusCode, String, Value) {
    let mut builder = Request::builder().uri("/whoami");
    if let Some(value) = auth_header {
        builder = builder.header("Authorization", value);
    }
    // Attach a fake ConnectInfo so middleware that reads peer addr
    // (none today on this trivial router, but the real wiring does)
    // never panics.
    let mut request = builder.body(Body::empty()).expect("request builds");
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )));
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body = String::from_utf8(bytes.to_vec()).expect("body is utf-8");
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    (status, body, parsed)
}

#[tokio::test]
#[ignore = "requires a running Zitadel + OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET"]
async fn oidc_zitadel_happy_and_failure_paths() {
    let env = match zitadel_env() {
        Ok(env) => env,
        Err(reason) => {
            eprintln!("[oidc_zitadel] skipping: {reason}");
            return;
        }
    };

    // 1) Mint a real token against Zitadel.
    let token = mint_zitadel_token(&env).await;
    let payload = decode_jwt_payload(&token);
    let aud = audience_from_payload(&payload);
    assert!(
        !aud.is_empty(),
        "minted token must carry at least one aud value: {payload}"
    );
    let expected_sub = payload
        .get("sub")
        .and_then(Value::as_str)
        .expect("minted token has sub claim")
        .to_string();

    // 2) Happy path: verifier configured with the real issuer + the
    //    token's actual audience accepts the token.
    let cfg = oidc_config(&env, aud.clone());
    let provider = build_provider(&cfg).await;
    let router = router_with_provider(Arc::clone(&provider));
    let (status, body, parsed) = send_request(router, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, StatusCode::OK, "happy path body={body}");
    assert!(
        !body.contains(&token),
        "successful response must not echo the bearer token"
    );
    assert_eq!(
        parsed["auth_mode"].as_str(),
        Some("oidc"),
        "principal carries oidc auth_mode"
    );
    assert_eq!(
        parsed["principal_id"].as_str(),
        Some(expected_sub.as_str()),
        "principal_id mirrors the JWT sub"
    );
    assert!(
        provider.key_count() >= 1,
        "JWKS cache populated after happy-path verify"
    );

    // 3) Tampered signature: same provider, mutated token.
    let bad_token = tamper_signature(&token);
    let router = router_with_provider(Arc::clone(&provider));
    let (status, _, parsed) = send_request(router, Some(&format!("Bearer {bad_token}"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "tampered: status");
    assert_eq!(
        parsed["code"].as_str(),
        Some("auth.token_signature_invalid"),
        "tampered: code"
    );

    // 4) Audience mismatch: verifier configured with an audience the
    //    IdP does not include.
    let bogus_aud_cfg = oidc_config(&env, vec!["urn:registry-relay:wrong-audience".to_string()]);
    let bogus_aud_provider = build_provider(&bogus_aud_cfg).await;
    let router = router_with_provider(Arc::clone(&bogus_aud_provider));
    let (status, _, parsed) = send_request(router, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "audience: status");
    assert_eq!(
        parsed["code"].as_str(),
        Some("auth.audience_mismatch"),
        "audience: code"
    );

    // 5) Issuer mismatch: verifier configured with a bogus issuer but
    //    still pointed at the real JWKS so signature verification
    //    passes and the failure mode is purely the iss claim check.
    let mut bogus_iss_cfg = oidc_config(&env, aud);
    bogus_iss_cfg.issuer = "https://wrong-issuer.example.test".to_string();
    let bogus_iss_provider = build_provider(&bogus_iss_cfg).await;
    let router = router_with_provider(Arc::clone(&bogus_iss_provider));
    let (status, _, parsed) = send_request(router, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "issuer: status");
    assert_eq!(
        parsed["code"].as_str(),
        Some("auth.issuer_mismatch"),
        "issuer: code"
    );

    // 6) Missing credential: no Authorization header.
    let router = router_with_provider(provider);
    let (status, _, parsed) = send_request(router, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing: status");
    assert_eq!(
        parsed["code"].as_str(),
        Some("auth.missing_credential"),
        "missing: code"
    );
}
