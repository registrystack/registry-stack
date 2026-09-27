#![cfg(feature = "test-authorization-server")]
//! The in-process test authorization server, driven over HTTP the way a
//! relying party, a resource server and a token-exchanging service use a real
//! one.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_platform_httputil::{
    BearerToken, ExchangeAuthorization, ExchangeContext, FetchUrlPolicy, OAuthErrorCode,
    PrivateKeyJwt, PrivateKeyJwtConfig, SubjectTokenType, TokenError, TokenProvider,
    UpstreamSubjectToken,
};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, VerifiedToken};
use registry_platform_testing::{
    ExchangeProfile, TestActorKind, TestAuthorizationServer, TestClient,
};
use reqwest::{redirect::Policy, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CHAT_HOST: &str = "chat-host";
const GATEWAY: &str = "gateway";
const OTHER_SERVICE: &str = "other-service";
const REDIRECT_URI: &str = "http://127.0.0.1:9/callback";
const GATEWAY_AUDIENCE: &str = "https://gateway.example";
const REGISTRY_AUDIENCE: &str = "https://registry.example";
const OTHER_AUDIENCE: &str = "https://other.example";
const GATEWAY_ACTOR: &str = "7f7c1c1e-3f0e-4d55-9a61-1a3a5f3b9d10";
const CITIZEN: &str = "citizen-1";
const VERIFIER: &str = "a-test-code-verifier-of-sufficient-length-0123456789";
const ACCESS_TOKEN_URN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

struct Fixture {
    server: TestAuthorizationServer,
    gateway_key: PrivateJwk,
    other_key: PrivateJwk,
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

fn client_key() -> PrivateJwk {
    generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("a client key generates")
}

async fn fixture_with(profile: ExchangeProfile) -> Fixture {
    let gateway_key = client_key();
    let other_key = client_key();
    let server = TestAuthorizationServer::builder()
        .client(
            TestClient::new(CHAT_HOST)
                .with_redirect_uri(REDIRECT_URI)
                .with_resource(GATEWAY_AUDIENCE)
                .with_actor_kind(TestActorKind::Human)
                .with_token_lifetime(Duration::from_secs(60)),
        )
        .client(
            TestClient::new(GATEWAY)
                .with_public_jwk(gateway_key.public())
                .with_resource(REGISTRY_AUDIENCE)
                .with_actor_kind(TestActorKind::Agent)
                .with_service_subject(GATEWAY_ACTOR)
                .with_token_lifetime(Duration::from_secs(3600)),
        )
        .client(
            TestClient::new(OTHER_SERVICE)
                .with_public_jwk(other_key.public())
                .with_resource(OTHER_AUDIENCE)
                .with_actor_kind(TestActorKind::Service),
        )
        .exchange_profile(profile)
        .start()
        .await;
    Fixture {
        server,
        gateway_key,
        other_key,
    }
}

async fn fixture() -> Fixture {
    fixture_with(ExchangeProfile::Conformant).await
}

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("the test HTTP client builds")
}

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a compact JWT");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url claims"))
        .expect("JSON claims")
}

fn header_of(token: &str) -> Value {
    let header = token.split('.').next().expect("a compact JWT");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).expect("base64url header"))
        .expect("JSON header")
}

/// The token text of a `BearerToken`, read the only way the type allows.
fn bearer_text(token: &BearerToken) -> String {
    token
        .authorization_header_value()
        .to_str()
        .expect("a visible ASCII header")
        .strip_prefix("Bearer ")
        .expect("a bearer header")
        .to_owned()
}

async fn authorize(server: &TestAuthorizationServer, params: &[(&str, &str)]) -> reqwest::Response {
    http()
        .get(server.authorization_endpoint())
        .query(params)
        .send()
        .await
        .expect("the authorization endpoint answers")
}

fn default_authorize_params(challenge: &str) -> Vec<(&str, &str)> {
    vec![
        ("response_type", "code"),
        ("client_id", CHAT_HOST),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "opaque-state"),
        ("scope", "openid records:read"),
        ("resource", GATEWAY_AUDIENCE),
        ("nonce", "opaque-nonce"),
        ("login_hint", CITIZEN),
    ]
}

/// Follow `/authorize` to its redirect and return the query it carries.
fn redirect_query(response: &reqwest::Response) -> BTreeMap<String, String> {
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("a redirect location")
        .to_str()
        .expect("an ASCII location");
    assert!(
        location.starts_with(&format!("{REDIRECT_URI}?")),
        "redirected to the registered URI only"
    );
    url::Url::parse(location)
        .expect("an absolute location")
        .query_pairs()
        .into_owned()
        .collect()
}

async fn post_form(server: &TestAuthorizationServer, form: &[(&str, &str)]) -> (StatusCode, Value) {
    let response = http()
        .post(server.token_endpoint())
        .form(form)
        .send()
        .await
        .expect("the token endpoint answers");
    let status = response.status();
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "every token endpoint response is uncacheable"
    );
    (status, response.json().await.expect("a JSON body"))
}

async fn redeem(
    server: &TestAuthorizationServer,
    code: &str,
    verifier: &str,
) -> (StatusCode, Value) {
    post_form(
        server,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CHAT_HOST),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
    )
    .await
}

/// A citizen's access token for the gateway, obtained by the public client's
/// authorization-code flow.
async fn citizen_token(server: &TestAuthorizationServer) -> String {
    let challenge = challenge(VERIFIER);
    let response = authorize(server, &default_authorize_params(&challenge)).await;
    let query = redirect_query(&response);
    let (status, body) = redeem(server, &query["code"], VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["access_token"].as_str().unwrap().to_owned()
}

/// A client assertion signed by hand, for the requests `PrivateKeyJwt`
/// deliberately cannot make.
fn assertion(key: &PrivateJwk, client_id: &str, audience: &str, jti: &str) -> String {
    let now = now_unix_seconds();
    let header = json!({"alg": key.algorithm().unwrap().jwa_name(), "kid": key.kid, "typ": "JWT"});
    let claims = json!({"iss": client_id, "sub": client_id, "aud": audience,
        "iat": now, "exp": now + 60, "jti": jti});
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = sign(input.as_bytes(), key).expect("the client key signs");
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn provider(
    server: &TestAuthorizationServer,
    client_id: &str,
    key: &PrivateJwk,
    resource: Option<&str>,
    scopes: &[&str],
) -> PrivateKeyJwt {
    let mut config = PrivateKeyJwtConfig::new(
        server.token_endpoint().parse().unwrap(),
        client_id,
        key.clone(),
    );
    if let Some(resource) = resource {
        config = config.with_resource(resource);
    }
    if !scopes.is_empty() {
        config = config.with_scopes(scopes.iter().copied());
    }
    PrivateKeyJwt::new(config).expect("the client provider builds")
}

fn upstream(
    fixture: &Fixture,
    citizen: &str,
    actor: Option<Arc<PrivateKeyJwt>>,
) -> ExchangeAuthorization {
    let claims = claims_of(citizen);
    let expires_at = claims["exp"].as_i64().unwrap();
    ExchangeAuthorization::upstream(
        provider(
            &fixture.server,
            GATEWAY,
            &fixture.gateway_key,
            Some(REGISTRY_AUDIENCE),
            &["records:read"],
        ),
        ExchangeContext::first_party(
            fixture.server.issuer(),
            CITIZEN,
            GATEWAY_AUDIENCE,
            "verified-inbound-token",
            expires_at,
        )
        .unwrap(),
        UpstreamSubjectToken::new(citizen, SubjectTokenType::AccessToken, expires_at).unwrap(),
        actor,
    )
    .expect("the upstream exchange is configured")
}

fn gateway_actor(fixture: &Fixture) -> Arc<PrivateKeyJwt> {
    Arc::new(provider(
        &fixture.server,
        GATEWAY,
        &fixture.gateway_key,
        None,
        &[],
    ))
}

async fn verifier(server: &TestAuthorizationServer, audience: &str) -> TokenVerifier {
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        server.jwks_uri(),
        JwksFetcherConfig {
            cache_ttl: Duration::from_secs(60),
            negative_cache_ttl: Duration::from_millis(1),
            refresh_cooldown: Duration::from_millis(1),
            max_doc_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(5),
            outage_tolerance: Duration::from_secs(900),
        },
        FetchUrlPolicy::dev(),
    ));
    let mut config = server.verifier_config(vec![audience.to_owned()]);
    config.allowed_clients = vec![CHAT_HOST.to_owned(), GATEWAY.to_owned()];
    TokenVerifier::new(config, fetcher)
}

async fn verified(server: &TestAuthorizationServer, audience: &str, token: &str) -> VerifiedToken {
    verifier(server, audience)
        .await
        .verify(token)
        .await
        .expect("the resource server accepts the token")
}

#[tokio::test]
async fn metadata_and_jwks_describe_the_server() {
    let fixture = fixture().await;
    let server = &fixture.server;
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let metadata: Value = http()
            .get(format!("{}{path}", server.issuer()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["issuer"], server.issuer());
        assert_eq!(
            metadata["authorization_endpoint"],
            server.authorization_endpoint()
        );
        assert_eq!(metadata["token_endpoint"], server.token_endpoint());
        assert_eq!(metadata["jwks_uri"], server.jwks_uri());
        assert_eq!(metadata["response_types_supported"], json!(["code"]));
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert_eq!(
            metadata["grant_types_supported"],
            json!(["authorization_code", "client_credentials", TOKEN_EXCHANGE])
        );
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            json!(["private_key_jwt", "none"])
        );
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
    }
    assert_eq!(
        server.discovery_url(),
        format!("{}/.well-known/openid-configuration", server.issuer())
    );
    let jwks: Value = http()
        .get(server.jwks_uri())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert!(
        keys[0].get("d").is_none(),
        "the JWKS publishes no private member"
    );
}

#[tokio::test]
async fn authorization_code_with_pkce_issues_tokens_the_oidc_verifier_accepts() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let challenge = challenge(VERIFIER);
    let response = authorize(server, &default_authorize_params(&challenge)).await;
    let query = redirect_query(&response);
    assert_eq!(query["state"], "opaque-state");
    assert_eq!(query["iss"], server.issuer());
    let (status, body) = redeem(server, &query["code"], VERIFIER).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "openid records:read");
    let expires_in = body["expires_in"].as_i64().unwrap();
    assert!((59..=60).contains(&expires_in));

    let access = body["access_token"].as_str().unwrap();
    assert_eq!(header_of(access)["typ"], "at+jwt");
    let token = verified(server, GATEWAY_AUDIENCE, access).await;
    assert_eq!(token.claims.sub.as_deref(), Some(CITIZEN));
    assert_eq!(token.matched_client_id().unwrap(), Some(CHAT_HOST));
    assert_eq!(token.scopes, ["openid", "records:read"]);
    let claims = claims_of(access);
    assert_eq!(claims["aud"], GATEWAY_AUDIENCE, "a single audience string");
    assert_eq!(claims["azp"], CHAT_HOST);
    assert_eq!(claims["client_id"], CHAT_HOST);
    assert_eq!(claims["registry_actor_kind"], "human");
    assert!(claims.get("act").is_none());

    let id_token = body["id_token"].as_str().expect("an ID token for openid");
    let id_claims = claims_of(id_token);
    assert_eq!(id_claims["aud"], CHAT_HOST);
    assert_eq!(id_claims["sub"], CITIZEN);
    assert_eq!(id_claims["nonce"], "opaque-nonce");
    assert_eq!(header_of(id_token)["typ"], "JWT");
}

#[tokio::test]
async fn a_logged_in_subject_is_used_without_a_login_hint() {
    let server = TestAuthorizationServer::builder()
        .client(
            TestClient::new(CHAT_HOST)
                .with_redirect_uri(REDIRECT_URI)
                .with_resource(GATEWAY_AUDIENCE),
        )
        .logged_in_subject("citizen-logged-in")
        .start()
        .await;
    let challenge = challenge(VERIFIER);
    let mut params = default_authorize_params(&challenge);
    params.retain(|(name, _)| *name != "login_hint");
    let query = redirect_query(&authorize(&server, &params).await);
    let (_, body) = redeem(&server, &query["code"], VERIFIER).await;
    assert_eq!(
        claims_of(body["access_token"].as_str().unwrap())["sub"],
        "citizen-logged-in"
    );

    // With nobody logged in and no hint, the flow ends at the client with
    // `login_required`, never with a token for an invented subject.
    let anonymous = TestAuthorizationServer::builder()
        .client(
            TestClient::new(CHAT_HOST)
                .with_redirect_uri(REDIRECT_URI)
                .with_resource(GATEWAY_AUDIENCE),
        )
        .start()
        .await;
    let query = redirect_query(&authorize(&anonymous, &params).await);
    assert_eq!(query["error"], "login_required");
    assert!(!query.contains_key("code"));
}

#[tokio::test]
async fn a_wrong_pkce_verifier_is_refused() {
    let fixture = fixture().await;
    let challenge = challenge(VERIFIER);
    let query =
        redirect_query(&authorize(&fixture.server, &default_authorize_params(&challenge)).await);
    let (status, body) = redeem(
        &fixture.server,
        &query["code"],
        "another-code-verifier-of-sufficient-length-0123456789",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn only_the_s256_challenge_method_is_accepted() {
    let fixture = fixture().await;
    let challenge = challenge(VERIFIER);
    for method in [None, Some("plain")] {
        let mut params = default_authorize_params(&challenge);
        params.retain(|(name, _)| *name != "code_challenge_method");
        if let Some(method) = method {
            params.push(("code_challenge_method", method));
        }
        let query = redirect_query(&authorize(&fixture.server, &params).await);
        assert_eq!(query["error"], "invalid_request", "method {method:?}");
        assert_eq!(query["state"], "opaque-state");
    }
}

#[tokio::test]
async fn an_authorization_code_is_used_once() {
    let fixture = fixture().await;
    let challenge = challenge(VERIFIER);
    let query =
        redirect_query(&authorize(&fixture.server, &default_authorize_params(&challenge)).await);
    let (first, _) = redeem(&fixture.server, &query["code"], VERIFIER).await;
    assert_eq!(first, StatusCode::OK);
    let (second, body) = redeem(&fixture.server, &query["code"], VERIFIER).await;
    assert_eq!(second, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn the_redirect_uri_must_match_exactly() {
    let fixture = fixture().await;
    let challenge = challenge(VERIFIER);
    for redirect in [
        "http://127.0.0.1:9/callback/",
        "http://127.0.0.1:9/callback?extra=1",
        "http://localhost:9/callback",
    ] {
        let mut params = default_authorize_params(&challenge);
        params.retain(|(name, _)| *name != "redirect_uri");
        params.push(("redirect_uri", redirect));
        let response = authorize(&fixture.server, &params).await;
        // An unregistered redirect is reported to the user agent, never
        // followed.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{redirect}");
        assert!(response.headers().get(reqwest::header::LOCATION).is_none());
    }

    // The token request must repeat the exact URI the code was issued for.
    let query =
        redirect_query(&authorize(&fixture.server, &default_authorize_params(&challenge)).await);
    let (status, body) = post_form(
        &fixture.server,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CHAT_HOST),
            ("code", &query["code"]),
            ("redirect_uri", "http://127.0.0.1:9/callback/"),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn an_unknown_client_is_refused() {
    let fixture = fixture().await;
    let challenge = challenge(VERIFIER);
    let mut params = default_authorize_params(&challenge);
    params.retain(|(name, _)| *name != "client_id");
    params.push(("client_id", "unregistered"));
    let response = authorize(&fixture.server, &params).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response.headers().get(reqwest::header::LOCATION).is_none());

    let unknown = provider(&fixture.server, "unregistered", &client_key(), None, &[]);
    assert!(matches!(
        unknown.bearer_token().await,
        Err(TokenError::Refused {
            code: OAuthErrorCode::InvalidClient
        })
    ));
}

#[tokio::test]
async fn a_bad_client_assertion_is_refused() {
    let fixture = fixture().await;
    let server = &fixture.server;
    // Signed by a key the client did not register.
    let impostor = provider(server, GATEWAY, &fixture.other_key, None, &[]);
    assert!(matches!(
        impostor.bearer_token().await,
        Err(TokenError::Refused {
            code: OAuthErrorCode::InvalidClient
        })
    ));

    let token_endpoint = server.token_endpoint();
    let cases = [
        // Addressed to another server.
        assertion(
            &fixture.gateway_key,
            GATEWAY,
            "https://elsewhere.example/token",
            "jti-1",
        ),
        // Naming another client than the one it authenticates.
        assertion(
            &fixture.gateway_key,
            OTHER_SERVICE,
            &token_endpoint,
            "jti-2",
        ),
        // Not a JWT at all.
        "not-a-jwt".to_owned(),
    ];
    for client_assertion in &cases {
        let (status, body) = post_form(
            server,
            &[
                ("grant_type", "client_credentials"),
                ("client_id", GATEWAY),
                ("client_assertion_type", JWT_BEARER),
                ("client_assertion", client_assertion),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    // A good assertion is accepted once; its replay is refused.
    let good = assertion(&fixture.gateway_key, GATEWAY, &token_endpoint, "jti-once");
    let form = [
        ("grant_type", "client_credentials"),
        ("client_id", GATEWAY),
        ("client_assertion_type", JWT_BEARER),
        ("client_assertion", good.as_str()),
    ];
    assert_eq!(post_form(server, &form).await.0, StatusCode::OK);
    let (status, body) = post_form(server, &form).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");

    // A confidential client cannot fall back to public-client redemption.
    let (status, body) = post_form(
        server,
        &[("grant_type", "client_credentials"), ("client_id", GATEWAY)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn client_credentials_names_the_service_subject() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let scoped = provider(
        server,
        GATEWAY,
        &fixture.gateway_key,
        Some(REGISTRY_AUDIENCE),
        &["records:read"],
    );
    let token = bearer_text(&scoped.bearer_token().await.unwrap());
    let verified = verified(server, REGISTRY_AUDIENCE, &token).await;
    assert_eq!(verified.claims.sub.as_deref(), Some(GATEWAY_ACTOR));
    assert_eq!(verified.matched_client_id().unwrap(), Some(GATEWAY));
    assert_eq!(claims_of(&token)["registry_actor_kind"], "agent");

    // Without a resource, the credential is addressed to this server only.
    let actor = gateway_actor(&fixture);
    let token = bearer_text(&actor.bearer_token().await.unwrap());
    assert_eq!(claims_of(&token)["aud"], server.issuer());
}

#[tokio::test]
async fn a_resource_the_client_may_not_address_is_refused() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let credentials = provider(
        server,
        GATEWAY,
        &fixture.gateway_key,
        Some(OTHER_AUDIENCE),
        &["records:read"],
    );
    assert!(matches!(
        credentials.bearer_token().await,
        Err(TokenError::Refused {
            code: OAuthErrorCode::Other
        })
    ));
    let (status, body) = post_form(
        server,
        &[
            ("grant_type", "client_credentials"),
            ("client_id", GATEWAY),
            ("client_assertion_type", JWT_BEARER),
            (
                "client_assertion",
                &assertion(
                    &fixture.gateway_key,
                    GATEWAY,
                    &server.token_endpoint(),
                    "jti-r",
                ),
            ),
            ("resource", OTHER_AUDIENCE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");

    let challenge = challenge(VERIFIER);
    let mut params = default_authorize_params(&challenge);
    params.retain(|(name, _)| *name != "resource");
    params.push(("resource", REGISTRY_AUDIENCE));
    let query = redirect_query(&authorize(server, &params).await);
    assert_eq!(query["error"], "invalid_target");

    let citizen = citizen_token(server).await;
    let (status, body) = post_form(
        server,
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("client_id", GATEWAY),
            ("client_assertion_type", JWT_BEARER),
            (
                "client_assertion",
                &assertion(
                    &fixture.gateway_key,
                    GATEWAY,
                    &server.token_endpoint(),
                    "jti-x",
                ),
            ),
            ("subject_token", &citizen),
            ("subject_token_type", ACCESS_TOKEN_URN),
            ("resource", OTHER_AUDIENCE),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_target");
}

#[tokio::test]
async fn token_exchange_issues_the_standing_agent_shape() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    let exchanged = upstream(&fixture, &citizen, Some(gateway_actor(&fixture)))
        .bearer_token()
        .await
        .expect("the exchange succeeds");
    let token = bearer_text(&exchanged);
    assert_eq!(header_of(&token)["typ"], "at+jwt");

    let verified = verified(server, REGISTRY_AUDIENCE, &token).await;
    assert_eq!(verified.claims.sub.as_deref(), Some(CITIZEN));
    assert_eq!(verified.matched_client_id().unwrap(), Some(GATEWAY));
    assert_eq!(verified.scopes, ["records:read"]);
    let claims = claims_of(&token);
    assert_eq!(
        claims["act"],
        json!({"sub": GATEWAY_ACTOR}),
        "exactly one member"
    );
    assert_eq!(claims["azp"], GATEWAY);
    assert_eq!(claims["client_id"], GATEWAY);
    assert_eq!(claims["aud"], REGISTRY_AUDIENCE);
    assert_eq!(claims["registry_actor_kind"], "agent");
    assert!(claims["exp"].as_i64().unwrap() <= claims_of(&citizen)["exp"].as_i64().unwrap());
}

#[tokio::test]
async fn an_exchange_without_an_actor_carries_no_act() {
    let fixture = fixture().await;
    let citizen = citizen_token(&fixture.server).await;
    let token = bearer_text(
        &upstream(&fixture, &citizen, None)
            .bearer_token()
            .await
            .unwrap(),
    );
    let claims = claims_of(&token);
    assert!(claims.get("act").is_none());
    assert_eq!(claims["sub"], CITIZEN);
}

#[tokio::test]
async fn the_exchanged_token_expires_with_its_subject_token() {
    // The citizen's client issues one-minute tokens and the gateway's issues
    // one-hour tokens. The exchanged token takes the earlier expiry.
    let fixture = fixture().await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    let subject_expiry = claims_of(&citizen)["exp"].as_i64().unwrap();
    let token = bearer_text(
        &upstream(&fixture, &citizen, Some(gateway_actor(&fixture)))
            .bearer_token()
            .await
            .unwrap(),
    );
    assert_eq!(claims_of(&token)["exp"].as_i64().unwrap(), subject_expiry);
}

#[tokio::test]
async fn an_expired_or_foreign_subject_token_is_refused() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let now = now_unix_seconds();
    let expired = server.issue_access_token(
        CHAT_HOST,
        CITIZEN,
        GATEWAY_AUDIENCE,
        "records:read",
        now - 1,
    );
    // Another server signing with the same key: only the issuer tells them
    // apart.
    let elsewhere = TestAuthorizationServer::builder()
        .client(TestClient::new(CHAT_HOST).with_resource(GATEWAY_AUDIENCE))
        .start()
        .await;
    let foreign = elsewhere.issue_access_token(
        CHAT_HOST,
        CITIZEN,
        GATEWAY_AUDIENCE,
        "records:read",
        now + 60,
    );
    for (label, subject) in [
        ("expired", expired),
        ("foreign", foreign),
        ("garbage", "a.b.c".to_owned()),
    ] {
        let (status, body) = post_form(
            server,
            &[
                ("grant_type", TOKEN_EXCHANGE),
                ("client_id", GATEWAY),
                ("client_assertion_type", JWT_BEARER),
                (
                    "client_assertion",
                    &assertion(
                        &fixture.gateway_key,
                        GATEWAY,
                        &server.token_endpoint(),
                        label,
                    ),
                ),
                ("subject_token", &subject),
                ("subject_token_type", ACCESS_TOKEN_URN),
                ("resource", REGISTRY_AUDIENCE),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(body["error"], "invalid_grant", "{label}");
    }
    elsewhere.stop().await;
}

#[tokio::test]
async fn an_actor_token_must_be_the_exchanging_clients_own_and_typed() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    let others = bearer_text(
        &provider(server, OTHER_SERVICE, &fixture.other_key, None, &[])
            .bearer_token()
            .await
            .unwrap(),
    );
    let own = bearer_text(&gateway_actor(&fixture).bearer_token().await.unwrap());
    let endpoint = server.token_endpoint();
    let cases: [(&str, &str, Option<&str>, &str); 3] = [
        (
            "another client's actor",
            &others,
            Some(ACCESS_TOKEN_URN),
            "invalid_grant",
        ),
        ("untyped actor", &own, None, "invalid_request"),
        (
            "forged actor",
            "a.b.c",
            Some(ACCESS_TOKEN_URN),
            "invalid_grant",
        ),
    ];
    for (label, actor, actor_type, error) in cases {
        let client_assertion = assertion(&fixture.gateway_key, GATEWAY, &endpoint, label);
        let mut form = vec![
            ("grant_type", TOKEN_EXCHANGE),
            ("client_id", GATEWAY),
            ("client_assertion_type", JWT_BEARER),
            ("client_assertion", client_assertion.as_str()),
            ("subject_token", citizen.as_str()),
            ("subject_token_type", ACCESS_TOKEN_URN),
            ("resource", REGISTRY_AUDIENCE),
            ("actor_token", actor),
        ];
        if let Some(actor_type) = actor_type {
            form.push(("actor_token_type", actor_type));
        }
        let (status, body) = post_form(server, &form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(body["error"], error, "{label}");
    }
}

#[tokio::test]
async fn a_scope_beyond_the_subject_token_is_refused() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    let (status, body) = post_form(
        server,
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("client_id", GATEWAY),
            ("client_assertion_type", JWT_BEARER),
            (
                "client_assertion",
                &assertion(
                    &fixture.gateway_key,
                    GATEWAY,
                    &server.token_endpoint(),
                    "jti-s",
                ),
            ),
            ("subject_token", &citizen),
            ("subject_token_type", ACCESS_TOKEN_URN),
            ("resource", REGISTRY_AUDIENCE),
            ("scope", "records:write"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn a_public_client_cannot_use_the_service_grants() {
    let fixture = fixture().await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    for grant in ["client_credentials", TOKEN_EXCHANGE] {
        let (status, body) = post_form(
            server,
            &[
                ("grant_type", grant),
                ("client_id", CHAT_HOST),
                ("subject_token", &citizen),
                ("subject_token_type", ACCESS_TOKEN_URN),
                ("resource", GATEWAY_AUDIENCE),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{grant}");
        assert_eq!(body["error"], "unauthorized_client", "{grant}");
    }
}

#[tokio::test]
async fn the_issuer_qualified_actor_profile_names_the_actor_issuer() {
    // Some authorization servers qualify `act` with the issuer and carry the
    // subject token's actor kind through unchanged. A test can select that
    // shape to exercise a resource server against it.
    let fixture = fixture_with(ExchangeProfile::IssuerQualifiedActor).await;
    let server = &fixture.server;
    let citizen = citizen_token(server).await;
    let token = bearer_text(
        &upstream(&fixture, &citizen, Some(gateway_actor(&fixture)))
            .bearer_token()
            .await
            .unwrap(),
    );
    let claims = claims_of(&token);
    assert_eq!(
        claims["act"],
        json!({"sub": GATEWAY_ACTOR, "iss": server.issuer()})
    );
    assert_eq!(claims["registry_actor_kind"], "human");
    assert_eq!(claims["client_id"], GATEWAY);
    assert_eq!(claims["sub"], CITIZEN);
}
