// SPDX-License-Identifier: Apache-2.0

use super::preauth_support::*;
use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, auth::*, credentials::*, federation::*, http_contracts::*, oid4vci::*,
};

#[tokio::test]
pub(super) async fn preauth_offer_start_redirects_to_esignet_and_mints_nothing() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("redirect location")
        .to_str()
        .expect("location is valid")
        .to_string();
    assert!(location.starts_with(&format!("{}/authorize", idp.issuer())));
    assert_eq!(
        query_param(&location, "response_type").as_deref(),
        Some("code")
    );
    assert_eq!(
        query_param(&location, "client_id").as_deref(),
        Some(ESIGNET_RP_CLIENT_ID)
    );
    assert_eq!(
        query_param(&location, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(query_param(&location, "state").is_some());
    assert!(query_param(&location, "nonce").is_some());
    assert!(query_param(&location, "claims").is_none());
    // No code or PIN is in the redirect; nothing is minted.
    assert!(!location.contains("pre-authorized_code"));

    // The audit log carries no minted material from a start.
    let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(!audit.contains("pre-authorized_code"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_offer_start_returns_429_when_login_state_store_is_full() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for _ in 0..4096 {
        server
            .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
            .await
            .assert_status(StatusCode::SEE_OTHER);
    }

    let limited = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.json::<Value>()["error"],
        json!("temporarily_unavailable")
    );
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_offer_start_requests_userinfo_subject_binding_claim_when_required() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.subject_access.subject_binding.claim_source = SubjectAccessClaimSource::Userinfo;
    config.subject_access.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("redirect location")
        .to_str()
        .expect("location is valid")
        .to_string();
    let claims =
        query_param(&location, "claims").expect("redirect requests required userinfo claim");
    let claims: Value = serde_json::from_str(&claims).expect("claims param is JSON");
    assert_eq!(
        claims,
        json!({
            "userinfo": {
                "individual_id": {
                    "essential": true
                }
            }
        })
    );
    assert!(!location.contains("pre-authorized_code"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_offer_start_rejects_unknown_configuration_id() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=unknown_config")
        .await;
    start.assert_status(StatusCode::BAD_REQUEST);
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_credential_rejects_inline_jwk_holder_proof_before_auth() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let response = server
        .post("/oid4vci/credential")
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": sign_oid4vci_inline_jwk_proof(NOTARY_ISSUER, "transaction-nonce")
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_proof"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_callback_mints_pre_authorized_offer_with_tx_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    assert!(!code.is_empty(), "callback mints a pre-authorized_code");
    assert_eq!(
        jwt_payload(&code)["tx_code_required"],
        json!(true),
        "the signed offer code binds its PIN requirement"
    );
    assert_eq!(pin.len(), 6, "tx_code is a 6-digit PIN");
    assert!(pin.chars().all(|c| c.is_ascii_digit()));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_callback_omits_tx_code_when_optional() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let page = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    assert!(
        !page.code.is_empty(),
        "callback mints a pre-authorized_code"
    );
    assert!(page.pin.is_none(), "offer page does not show a PIN");
    assert!(
        !page.html.contains("id=\"tx-code\""),
        "optional tx_code mode omits the PIN block"
    );
    assert!(
        page.offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"]
            .is_null(),
        "credential offer omits the tx_code object"
    );
    idp.stop().await;
}

/// eSignet signs ID Tokens with a JOSE header that omits the optional `typ`
/// member (observed live: `{"alg":"PS256","kid":...}`). The pre-auth callback
/// must accept such an id_token and mint the offer. Regression guard for the
/// Wave 5 hosted blocker where a typ-less id_token was rejected as
/// `invalid_token` before the nonce/userinfo checks ran.
#[tokio::test]
pub(super) async fn preauth_callback_accepts_esignet_id_token_without_typ_header() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");

    // Mint the eSignet id_token WITHOUT a `typ` header, as eSignet does.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let id_token = idp.mint_token_without_typ(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "nonce": nonce,
        "national_id": "person-1",
        "scope": "openid subject_access",
        "acr": "urn:example:loa:substantial",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    // The test id_token must genuinely omit `typ` for this to exercise the fix.
    let header_b64 = id_token
        .split('.')
        .next()
        .expect("jwt has a header segment");
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_b64)
            .expect("header is base64url"),
    )
    .expect("header is JSON");
    assert!(
        header.get("typ").is_none(),
        "test id_token must omit the typ header"
    );

    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;

    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    callback.assert_status_ok();
    let html = callback.text();
    let offer_uri = extract_between(&html, "href=\"", "\"").expect("offer href present");
    let offer_json =
        query_param(&offer_uri, "credential_offer").expect("offer carries credential_offer");
    let offer: Value = serde_json::from_str(&offer_json).expect("offer is JSON");
    let code = offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
        ["pre-authorized_code"]
        .as_str()
        .expect("offer carries pre-authorized_code");
    assert!(
        !code.is_empty(),
        "a typ-less eSignet id_token still mints a pre-authorized_code"
    );
    idp.stop().await;
}

/// When the eSignet RP client signing key is RS256, the `private_key_jwt`
/// client assertion the Notary sends to the eSignet token endpoint must carry
/// header `alg: RS256` and verify against the RP RSA public key. This proves the
/// RS256 RP key path end to end: the callback exchanges the eSignet code, which
/// signs the assertion with the configured RS256 key.
#[cfg(feature = "registry-notary-cel")]
#[tokio::test]
pub(super) async fn preauth_client_assertion_is_rs256_signed_when_rp_key_is_rsa() {
    set_preauth_env();
    std::env::set_var("TEST_ESIGNET_RP_RSA_JWK", TEST_ESIGNET_RP_RSA_JWK);
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    // Swap the eSignet RP client signing key for an RSA/RS256 key.
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        SigningKeyConfig {
            provider: SigningKeyProviderConfig::LocalJwkEnv,
            alg: "RS256".to_string(),
            kid: "did:web:rp.example#esignet-rp-rsa-key".to_string(),
            status: SigningKeyStatus::Active,
            publish_until_unix_seconds: None,
            private_jwk_env: "TEST_ESIGNET_RP_RSA_JWK".to_string(),
            public_jwk_env: String::new(),
            module_path: String::new(),
            token_label: String::new(),
            pin_env: String::new(),
            key_label: String::new(),
            key_id_hex: String::new(),
            path: String::new(),
            password_env: String::new(),
        },
    );
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, _pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    assert!(!code.is_empty(), "callback mints a pre-authorized_code");

    // Capture the token-endpoint POST the Notary sent and pull out the
    // client_assertion form field.
    let requests = token_upstream
        .wiremock_server()
        .received_requests()
        .await
        .expect("wiremock records requests");
    let token_request = requests
        .iter()
        .find(|request| request.url.path() == "/token")
        .expect("the Notary posts to the eSignet token endpoint");
    let body = String::from_utf8(token_request.body.clone()).expect("token request body is UTF-8");
    let client_assertion = form_field(&body, "client_assertion")
        .expect("the token request carries a client_assertion");

    // The JOSE header alg must be RS256 (derived from the RP RSA key).
    let header = jwt_header(&client_assertion);
    assert_eq!(
        header["alg"], "RS256",
        "the client assertion is signed with the RP key's RS256 algorithm"
    );
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "did:web:rp.example#esignet-rp-rsa-key");

    // The signature must verify against the RP RSA public key.
    let rp_private = PrivateJwk::parse(TEST_ESIGNET_RP_RSA_JWK).expect("RP RSA JWK parses");
    let rp_public = rp_private.public();
    let mut segments = client_assertion.split('.');
    let header_b64 = segments.next().expect("assertion has a header segment");
    let payload_b64 = segments.next().expect("assertion has a payload segment");
    let signature_b64 = segments.next().expect("assertion has a signature segment");
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .expect("signature is base64url");
    verify(signing_input.as_bytes(), &signature, &rp_public)
        .expect("the RS256 client assertion verifies against the RP RSA public key");

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_token_endpoint_issues_access_token_and_c_nonce() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let body: Value = token.json();
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], json!("Bearer"));
    assert!(body["c_nonce"].is_string());
    assert_eq!(body["expires_in"], json!(300));

    let access_token = body["access_token"].as_str().expect("access token minted");
    let claims = jwt_payload(access_token);
    assert_eq!(
        claims["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    let scopes: BTreeSet<&str> = claims["scope"]
        .as_str()
        .expect("scope claim is present")
        .split(' ')
        .collect();
    assert!(scopes.contains("subject_access"));
    assert!(scopes.contains("person-is-alive"));
    assert_eq!(
        claims["authorization_details"][0]["type"],
        json!("registry_notary_evidence_transaction")
    );
    assert_eq!(
        claims["authorization_details"][0]["schema_version"],
        json!("registry-notary-authorization-details/v1")
    );
    assert_eq!(
        claims["authorization_details"][0]["actions"],
        json!(["evaluate"])
    );
    assert_eq!(
        claims["authorization_details"][0]["locations"],
        json!(["evidence.test"])
    );
    assert_eq!(
        claims["authorization_details"][0]["claims"][0]["id"],
        json!("person-is-alive")
    );
    assert_eq!(
        claims["authorization_details"][0]["disclosure"],
        json!("value")
    );
    assert_eq!(
        claims["authorization_details"][0]["format"],
        json!("application/vnd.registry-notary.claim-result+json")
    );
    assert_eq!(
        claims["authorization_details"][0]["purpose"],
        json!("citizen_subject_access")
    );
    assert_eq!(
        claims["authorization_details"][0]["access_mode"],
        json!("subject_bound")
    );
    assert_eq!(
        claims["authorization_details"][0]["subject"],
        json!({
            "binding_claim": "national_id",
            "id_type": "national_id"
        })
    );
    idp.stop().await;
}

/// Issue #173: when the access-token signing key and a credential-profile
/// signing key resolve to the same Ed25519 material under distinct ids and
/// kids, server startup must fail through the real build path
/// (`compile_notary_runtime` -> `SigningKeyRegistry::from_config`), not just the
/// in-isolation helper. The eSignet RP client key is excluded from this scope by
/// `admin_config_apply_signed_preauth_signing_rotation_preserves_inflight_tokens`.
#[tokio::test]
pub(super) async fn compile_rejects_access_token_key_reusing_credential_key_material() {
    set_preauth_env();
    // A dedicated env var bound to the credential issuer's material. The
    // credential `issuer-key` resolves from `TEST_SELF_ATTESTATION_ISSUER_JWK`,
    // which `set_preauth_env` also sets to `TEST_ISSUER_JWK`, so the new
    // access-token key reuses the credential key material under a distinct
    // id/kid.
    std::env::set_var("TEST_ACCESS_TOKEN_REUSES_CREDENTIAL_JWK", TEST_ISSUER_JWK);
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    );
    config.evidence.signing_keys.insert(
        "access-token-key-reuses-credential".to_string(),
        local_jwk_signing_key(
            "TEST_ACCESS_TOKEN_REUSES_CREDENTIAL_JWK",
            "did:web:issuer.example#access-token-key-reuses-credential",
        ),
    );
    config.auth.access_token_signing.signing_key_id =
        "access-token-key-reuses-credential".to_string();

    let error = match compile_notary_runtime(config) {
        Ok(_) => panic!("reused signing key material must fail startup"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("reuses public key material"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("access-token-key-reuses-credential") || message.contains("issuer-key"),
        "error must name the colliding signing key ids: {message}"
    );
    // The error must never leak key material (thumbprint or raw JWK coordinate).
    assert!(
        !message.contains(TEST_ISSUER_JWK),
        "error must not contain raw key material"
    );
    idp.stop().await;
}

/// A userinfo-sourced subject binding (`claim_source = userinfo`) reads the
/// binding claim from the eSignet userinfo JWS, not the `id_token`. This mirrors
/// the hosted lab, where eSignet delivers `individual_id` only via userinfo.
#[tokio::test]
pub(super) async fn preauth_callback_binds_subject_from_userinfo_when_claim_source_is_userinfo() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.subject_access.subject_binding.claim_source = SubjectAccessClaimSource::Userinfo;
    config.subject_access.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // The id_token (minted by drive_offer_to_code) carries no individual_id;
    // the userinfo JWS supplies it, bound to the same subject.
    let userinfo = idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "individual_id": "civil-id-9001",
    }));
    token_upstream
        .expect("GET", "/userinfo")
        .respond_body(200, userinfo)
        .await;

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let body: Value = token.json();
    let access_token = body["access_token"].as_str().expect("access token minted");
    let claims = jwt_payload(access_token);
    assert_eq!(
        claims["individual_id"],
        json!("civil-id-9001"),
        "subject binding must come from the userinfo JWS, not the id_token"
    );
    idp.stop().await;
}

/// When the subject binding is userinfo-sourced but the userinfo JWS omits the
/// binding claim, the callback denies the login and mints no code.
#[tokio::test]
pub(super) async fn preauth_callback_denies_when_userinfo_lacks_subject_binding_claim() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.subject_access.subject_binding.claim_source = SubjectAccessClaimSource::Userinfo;
    config.subject_access.subject_binding.token_claim = "individual_id".to_string();
    config.oid4vci.pre_authorized_code.esignet.userinfo_url =
        format!("{}/userinfo", token_upstream.url());
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(format!("{}/userinfo", token_upstream.url()));
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // userinfo JWS bound to the subject but without the binding claim.
    let userinfo = idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
    }));
    token_upstream
        .expect("GET", "/userinfo")
        .respond_body(200, userinfo)
        .await;

    let start = server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    start.assert_status(StatusCode::SEE_OTHER);
    let location = start
        .headers()
        .get("location")
        .expect("offer start redirects")
        .to_str()
        .expect("location is valid")
        .to_string();
    let state = query_param(&location, "state").expect("redirect carries state");
    let nonce = query_param(&location, "nonce").expect("redirect carries nonce");
    let id_token = esignet_id_token(&idp, &nonce, "person-1");
    token_upstream
        .expect("POST", "/token")
        .respond_json(
            200,
            json!({
                "access_token": "esignet-access-token",
                "token_type": "Bearer",
                "id_token": id_token,
                "expires_in": 300,
            }),
        )
        .await;
    let callback = server
        .get(&format!(
            "/oid4vci/offer/callback?code=esignet-code-123&state={state}"
        ))
        .await;
    assert_ne!(
        callback.status_code(),
        StatusCode::OK,
        "a userinfo response missing the binding claim must deny the callback"
    );
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_code_is_single_use() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    redeem_token(&server, &code, &pin).await.assert_status_ok();
    let second = redeem_token(&server, &code, &pin).await;
    second.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = second.json();
    assert_eq!(body["error"], json!("invalid_grant"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_token_rejects_wrong_and_missing_tx_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, _pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;

    let wrong_pin = redeem_token(&server, &code, "000000").await;
    wrong_pin.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        wrong_pin.json::<Value>()["error"],
        json!("invalid_grant"),
        "a wrong tx_code is rejected"
    );

    let missing_pin = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}",
            urlencode(&code)
        ))
        .await;
    missing_pin.assert_status(StatusCode::BAD_REQUEST);
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_token_accepts_missing_tx_code_when_optional() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 0;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let page = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    assert!(
        page.pin.is_none(),
        "optional tx_code mode does not mint a PIN"
    );
    assert_eq!(
        jwt_payload(&page.code)["tx_code_required"],
        json!(false),
        "the signed offer code binds its no-PIN policy"
    );
    redeem_token_without_pin(&server, &page.code)
        .await
        .assert_status_ok();

    let second = redeem_token_without_pin(&server, &page.code).await;
    second.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(second.json::<Value>()["error"], json!("invalid_grant"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_signed_required_policy_and_lockout_survive_optional_runtime_config() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config.oid4vci.pre_authorized_code.tx_code.required = false;
    config
        .oid4vci
        .pre_authorized_code
        .pre_authorized_code_ttl_seconds = 120;
    config
        .subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 2;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let issued = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    let mut payload = jwt_payload(&issued.code);
    payload["jti"] = json!(Ulid::new().to_string());
    payload["tx_code_required"] = json!(true);
    let signed_required_code = sign_test_preauthorized_code(payload);

    for wrong_pin in ["111111", "222222"] {
        let response = redeem_token(&server, &signed_required_code, wrong_pin).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["error"], json!("invalid_grant"));
    }
    let locked = redeem_token(&server, &signed_required_code, "333333").await;
    locked.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(locked.json::<Value>()["error"], json!("slow_down"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_forged_optional_code_without_reserved_transaction_is_rejected() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let issued = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    let mut payload = jwt_payload(&issued.code);
    payload["jti"] = json!(Ulid::new().to_string());
    payload["tx_code_required"] = json!(false);
    let signed_optional_code = sign_test_preauthorized_code(payload);

    let response = redeem_token_without_pin(&server, &signed_optional_code).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["error"], json!("invalid_grant"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_token_rejects_missing_or_non_boolean_signed_tx_code_policy() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let issued = drive_offer_to_page(&server, &token_upstream, &idp, "person-1").await;
    let baseline = jwt_payload(&issued.code);
    for malformed_policy in [None, Some(json!("true"))] {
        let mut payload = baseline.clone();
        payload["jti"] = json!(Ulid::new().to_string());
        match malformed_policy {
            Some(value) => payload["tx_code_required"] = value,
            None => {
                payload
                    .as_object_mut()
                    .expect("JWT payload is an object")
                    .remove("tx_code_required");
            }
        }
        let response =
            redeem_token_without_pin(&server, &sign_test_preauthorized_code(payload)).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["error"], json!("invalid_grant"));
    }
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_repeated_wrong_pins_lock_the_code() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config
        .subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 2;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;

    // Two wrong attempts are within the cap; the third trips the limiter and the
    // code is locked, so even the correct PIN now fails.
    redeem_token(&server, &code, "111111")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    redeem_token(&server, &code, "222222")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let locked = redeem_token(&server, &code, &pin).await;
    locked.assert_status(StatusCode::TOO_MANY_REQUESTS);
    let body: Value = locked.json();
    assert_eq!(body["error"], json!("slow_down"));
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_token_rejects_wrong_and_missing_grant_cleanly() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let other_grant = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("grant_type=authorization_code&code=abc")
        .await;
    other_grant.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        other_grant.json::<Value>()["error"],
        json!("unsupported_grant_type")
    );

    let missing_grant = server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("foo=bar")
        .await;
    missing_grant.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_grant.json::<Value>()["error"],
        json!("invalid_request")
    );
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_random_code_flood_is_throttled_per_client_address() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_preauth_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    );
    config
        .subject_access
        .rate_limits
        .invalid_token_per_client_address_per_minute = 2;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Random codes from one socket peer: caller-supplied forwarding headers do
    // not create fresh buckets.
    let flood = |code: &str, forwarded_for: &str| {
        server
            .post("/oid4vci/token")
            .add_header("content-type", "application/x-www-form-urlencoded")
            .add_header("x-forwarded-for", forwarded_for)
            .text(format!(
                "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={code}&tx_code=000000"
            ))
    };
    flood("random-a", "203.0.113.50")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    flood("random-b", "203.0.113.51")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let throttled = flood("random-c", "203.0.113.52").await;
    throttled.assert_status(StatusCode::TOO_MANY_REQUESTS);
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_disabled_exposes_no_wallet_issuance_grant() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    // Default config: pre-auth disabled.
    let mut config = subject_access_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.oid4vci.enabled = false;
    config.oid4vci.pre_authorized_code = Default::default();
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/oid4vci/offer/start?credential_configuration_id=person_is_alive_sd_jwt")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/oid4vci/offer/callback?code=x&state=y")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=x&tx_code=1")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    server
        .get("/oid4vci/credential-offer")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/oid4vci/nonce")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // Disabling the only supported issuance grant disables issuer metadata.
    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status(StatusCode::NOT_FOUND);
    idp.stop().await;
}

/// Manually mint a Notary access token (header.payload.signature) so trust-anchor
/// tests can sign with the access-token key, the credential key, or a wrong key.
pub(super) fn mint_notary_access_token(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
) -> String {
    mint_notary_access_token_with_scope_and_authorization_details(
        private_jwk,
        kid,
        typ,
        issuer,
        national_id,
        "subject_access",
        None,
    )
}

pub(super) fn mint_notary_access_token_with_scope_and_authorization_details(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
    scope: &str,
    authorization_details: Option<Value>,
) -> String {
    mint_notary_access_token_with_jti_scope_and_authorization_details(
        private_jwk,
        kid,
        typ,
        issuer,
        national_id,
        None,
        scope,
        authorization_details,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn mint_notary_access_token_with_jti_scope_and_authorization_details(
    private_jwk: &str,
    kid: &str,
    typ: &str,
    issuer: &str,
    national_id: &str,
    jti: Option<&str>,
    scope: &str,
    authorization_details: Option<Value>,
) -> String {
    let key = PrivateJwk::parse(private_jwk).expect("test JWK parses");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let header = json!({ "alg": "EdDSA", "typ": typ, "kid": kid });
    let mut payload = json!({
        "iss": issuer,
        "aud": NOTARY_AUDIENCE,
        "sub": "esignet-citizen-subject",
        "client_id": ESIGNET_RP_CLIENT_ID,
        "scope": scope,
        "national_id": national_id,
        "token_type": "Bearer",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    });
    if let Some(jti) = jti {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("jti".to_string(), json!(jti));
    }
    if let Some(authorization_details) = authorization_details {
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("authorization_details".to_string(), authorization_details);
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = sign(signing_input.as_bytes(), &key).expect("token signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

pub(super) fn preauth_test_config(
    base_url: &str,
    audit_path: &str,
    idp: &MockIdp,
    token_upstream: &MockHttpUpstream,
) -> StandaloneRegistryNotaryConfig {
    subject_access_preauth_config(
        base_url,
        audit_path,
        &idp.issuer(),
        &idp.jwks_uri(),
        &format!("{}/authorize", idp.issuer()),
        &format!("{}/token", token_upstream.url()),
    )
}

#[tokio::test]
pub(super) async fn preauth_trust_anchor_rejects_wrong_key_and_credential_key_notary_tokens() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Use a protected route without a proof precheck, so the trust-anchor
    // verification alone decides the outcome.
    // A Notary-issuer token signed by the WRONG key (the holder key) is rejected.
    let wrong_key_token = mint_notary_access_token(
        TEST_HOLDER_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
    );
    server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {wrong_key_token}"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // A Notary-issuer token signed by the CREDENTIAL key is rejected (the second
    // anchor verifies only against the dedicated access-token key).
    let credential_key_token = mint_notary_access_token(
        TEST_ISSUER_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
    );
    server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {credential_key_token}"))
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_transaction_token_jti_denials_are_stable_and_redacted() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    );
    config.auth.access_token_signing.token_typ = NOTARY_TRANSACTION_TOKEN_JWT_TYP.to_string();
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let missing_jti_token = mint_notary_access_token(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        NOTARY_ISSUER,
        "person-1",
    );
    let missing_jti = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {missing_jti_token}"))
        .await;
    missing_jti.assert_status(StatusCode::UNAUTHORIZED);
    let missing_jti_body: Value = missing_jti.json();
    assert_eq!(missing_jti_body["code"], json!("auth.missing_credential"));
    assert!(missing_jti_body.get("data").is_none());
    assert!(!missing_jti_body.to_string().contains(&missing_jti_token));

    let replay_token = mint_notary_access_token_with_jti_scope_and_authorization_details(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        NOTARY_ISSUER,
        "person-1",
        Some("txn-jti-http-replay-1"),
        "subject_access",
        Some(json!([{
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "actions": ["evaluate"],
            "locations": ["evidence.test"]
        }])),
    );
    let first_use = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    first_use.assert_status_ok();
    let first_use_body: Value = first_use.json();
    assert!(first_use_body["data"].is_array());

    let replay = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    replay.assert_status(StatusCode::UNAUTHORIZED);
    let replay_body: Value = replay.json();
    assert_eq!(replay_body["code"], json!("auth.missing_credential"));
    assert!(replay_body.get("data").is_none());
    assert!(!replay_body.to_string().contains(&replay_token));
    assert!(!replay_body.to_string().contains("txn-jti-http-replay-1"));

    let multi_auth = server
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .add_header("authorization", format!("Bearer {replay_token}"))
        .await;
    multi_auth.assert_status(StatusCode::BAD_REQUEST);
    let multi_auth_body: Value = multi_auth.json();
    assert_eq!(multi_auth_body["code"], json!("auth.multiple_credentials"));
    assert!(multi_auth_body.get("data").is_none());
    assert!(!multi_auth_body.to_string().contains(&replay_token));
    assert!(!multi_auth_body.to_string().contains("api-token"));
    assert!(!multi_auth_body
        .to_string()
        .contains("txn-jti-http-replay-1"));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains(&missing_jti_token));
    assert!(!audit.contains(&replay_token));
    assert!(!audit.contains("api-token"));
    assert!(!audit.contains("txn-jti-http-replay-1"));
    assert!(!audit.contains("person-1"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    assert!(records
        .iter()
        .any(|record| record["path"] == json!("/v1/claims") && record["status"] == json!(200)));
    let missing_credential_denials = records
        .iter()
        .filter(|record| {
            record["path"] == json!("/v1/claims")
                && record["status"] == json!(401)
                && record["error_code"] == json!("auth.missing_credential")
        })
        .count();
    assert!(
        missing_credential_denials >= 2,
        "missing-jti and replay denials should both be audited: {records:?}"
    );
    assert!(records.iter().any(|record| {
        record["path"] == json!("/v1/claims")
            && record["status"] == json!(400)
            && record["error_code"] == json!("auth.multiple_credentials")
    }));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_trust_anchor_isolates_esignet_and_notary_paths() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // A token claiming the Notary issuer but actually an eSignet-minted token
    // fails: the Notary anchor verifies it against the access-token key only.
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let esignet_token_claiming_notary_iss = idp.mint_token(json!({
        "iss": NOTARY_ISSUER,
        "sub": "esignet-citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": ESIGNET_RP_CLIENT_ID,
        "scope": "subject_access",
        "national_id": "person-1",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    server
        .get("/v1/claims")
        .add_header(
            "authorization",
            format!("Bearer {esignet_token_claiming_notary_iss}"),
        )
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_existing_esignet_token_still_authenticates_credential_endpoint() {
    // The unchanged eSignet single-issuer path still accepts an eSignet token.
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    // An eSignet-issued token (issuer == eSignet) on the unchanged path.
    let esignet_token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": "citizen-portal",
        "scope": "subject_access",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    // It passes the protected JWKS route (auth succeeds) on the eSignet path.
    let jwks = server
        .get("/.well-known/evidence/jwks.json")
        .add_header("authorization", format!("Bearer {esignet_token}"))
        .await;
    jwks.assert_status_ok();
    idp.stop().await;
}

#[tokio::test]
pub(super) async fn preauth_notary_access_token_with_empty_authorization_details_cannot_issue_credential(
) {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let old_shape_token = mint_notary_access_token_with_scope_and_authorization_details(
        TEST_ACCESS_TOKEN_JWK,
        "did:web:issuer.example#access-token-key",
        "registry-notary-access+jwt",
        NOTARY_ISSUER,
        "person-1",
        "subject_access person-is-alive",
        Some(json!([])),
    );
    let proof = sign_oid4vci_proof(NOTARY_ISSUER, "unbound-legacy-nonce");

    let credential = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {old_shape_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": { "proof_type": "jwt", "jwt": proof }
        }))
        .await;

    credential.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(credential.json::<Value>()["error"], json!("access_denied"));
    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn preauth_end_to_end_issues_sd_jwt_vc_bound_to_holder() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Issuer metadata advertises the Notary token endpoint when pre-auth is
    // enabled, so a wallet discovers it can redeem the pre-authorized_code grant.
    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(
        metadata_body["token_endpoint"],
        json!("http://127.0.0.1:4325/oid4vci/token"),
        "enabled pre-auth advertises the Notary token endpoint"
    );

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let token_body: Value = token.json();
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();
    let c_nonce = token_body["c_nonce"]
        .as_str()
        .expect("c_nonce issued")
        .to_string();

    // The Notary-minted token is accepted at the credential endpoint and issues
    // an SD-JWT VC bound to the holder's did:jwk proof.
    let proof = sign_oid4vci_proof(NOTARY_ISSUER, &c_nonce);
    let credential_request = json!({
        "format": "dc+sd-jwt",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "proof": { "proof_type": "jwt", "jwt": proof }
    });
    let credential = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&credential_request)
        .await;
    credential.assert_status_ok();
    let credential_body: Value = credential.json();
    assert_eq!(credential_body["format"], json!("dc+sd-jwt"));
    assert!(credential_body.get("c_nonce").is_none());
    assert!(credential_body.get("c_nonce_expires_in").is_none());
    let sd_jwt = credential_body["credential"]
        .as_str()
        .expect("credential issued");
    assert!(sd_jwt.contains('~'), "an SD-JWT VC carries disclosures");
    let payload = decode_sd_jwt_payload(sd_jwt);
    assert!(
        payload["issuanceDate"].as_str().is_some(),
        "wallet-compatible issuance date alias is present"
    );
    assert!(
        payload["expirationDate"].as_str().is_some(),
        "wallet-compatible expiration date alias is present"
    );
    let retry = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&credential_request)
        .await;
    retry.assert_status_ok();
    assert_eq!(
        retry.json::<Value>(),
        credential_body,
        "an exact retry receives the verbatim cached credential response"
    );
    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn preauth_cached_retry_cannot_escape_failed_credential_audit() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let audit_backup_path = tmp.path().join("audit.backup.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    let token = redeem_token(&server, &code, &pin).await;
    token.assert_status_ok();
    let token_body: Value = token.json();
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();
    let nonce = token_body["c_nonce"]
        .as_str()
        .expect("transaction nonce issued");
    let credential_request = json!({
        "format": "dc+sd-jwt",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "proof": {
            "proof_type": "jwt",
            "jwt": sign_oid4vci_proof(NOTARY_ISSUER, nonce),
        }
    });

    // Preserve the valid retained chain, but temporarily replace its active
    // path with a directory so the first credential-issued append fails.
    std::fs::rename(&audit_path, &audit_backup_path).expect("audit file moves aside");
    std::fs::create_dir(&audit_path).expect("audit path becomes unwritable");
    let failed = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&credential_request)
        .await;
    failed.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.json::<Value>()["code"], json!("audit.write_failed"));

    std::fs::remove_dir(&audit_path).expect("temporary audit directory is removed");
    std::fs::rename(&audit_backup_path, &audit_path).expect("audit chain is restored");
    let recovered = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&credential_request)
        .await;
    recovered.assert_status_ok();
    let recovered_body: Value = recovered.json();
    let exact_retry = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&credential_request)
        .await;
    exact_retry.assert_status_ok();
    assert_eq!(
        exact_retry.json::<Value>(),
        recovered_body,
        "recovery and later exact retries use the one cached signature"
    );
    let issued_audits = audit_envelopes(&audit_path)
        .into_iter()
        .filter(|envelope| {
            envelope.record["path"] == json!("/oid4vci/credential")
                && envelope.record["decision"] == json!("credential_issued")
                && envelope.record["status"] == json!(200)
        })
        .count();
    assert_eq!(
        issued_audits, 2,
        "each released cached response must pass credential-issued audit emission"
    );
    idp.stop().await;
}

/// Decode the SD-JWT VC issuer JWS payload (the segment before the first `~`).
#[cfg(feature = "registry-notary-cel")]
pub(super) fn decode_sd_jwt_payload(sd_jwt: &str) -> Value {
    let issuer_jws = sd_jwt
        .split('~')
        .next()
        .expect("SD-JWT contains an issuer JWS");
    let payload_segment = issuer_jws
        .split('.')
        .nth(1)
        .expect("issuer JWS contains a payload segment");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("issuer JWS payload is base64url"),
    )
    .expect("issuer JWS payload is JSON")
}

/// Decode the SD-JWT VC disclosure for `claim_name` and return its value object.
/// A disclosure is `base64url([salt, name, value])`; the value is the evaluated
/// claim result.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn decode_disclosed_claim(sd_jwt: &str, claim_name: &str) -> Value {
    sd_jwt
        .split('~')
        .skip(1)
        .filter(|part| !part.is_empty())
        .find_map(|part| {
            let decoded = URL_SAFE_NO_PAD.decode(part).ok()?;
            let triple: Value = serde_json::from_slice(&decoded).ok()?;
            (triple.get(1).and_then(Value::as_str) == Some(claim_name))
                .then(|| triple.get(2).cloned())
                .flatten()
        })
        .unwrap_or_else(|| panic!("disclosure for {claim_name} is present"))
}

/// Find the single `credential_issued` audit record for the OID4VCI credential
/// endpoint. Its `target_ref_hash`/`requester_ref_hash` are HMACs over the
/// bound subject reference, deterministic for a fixed audit secret, so two paths
/// that bind the same eSignet subject produce identical hashes.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn credential_issued_audit(audit_path: &std::path::Path) -> Value {
    audit_envelopes(audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .find(|record| {
            record["path"] == json!("/oid4vci/credential")
                && record["decision"] == json!("credential_issued")
                && record["status"] == json!(200)
        })
        .expect("credential_issued audit record exists")
}

/// A wallet-issued eSignet bearer token cannot bypass the issuer-initiated
/// transaction, while the approved pre-authorized-code path binds and issues.
#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn preauth_transaction_cannot_be_bypassed_with_esignet_wallet_token() {
    set_preauth_env();

    // The eSignet-token (auth-code) baseline: an eSignet token whose
    // subject-binding claim is the same civil id the pre-auth login carries.
    let baseline_idp = MockIdp::start().await;
    let baseline_token_upstream = MockHttpUpstream::start().await;
    let baseline_tmp = TempDir::new().expect("tempdir");
    let baseline_audit_path = baseline_tmp.path().join("audit.jsonl");
    let baseline_app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        baseline_audit_path.to_str().expect("audit path is UTF-8"),
        &baseline_idp,
        &baseline_token_upstream,
    ))
    .await
    .expect("baseline router builds");
    let baseline_server = TestServer::builder().http_transport().build(baseline_app);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    // An eSignet-issued token bound to civil id "person-1" via national_id.
    let esignet_token = baseline_idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": NOTARY_AUDIENCE,
        "azp": "citizen-portal",
        "scope": "subject_access person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let baseline_proof = sign_oid4vci_proof(NOTARY_ISSUER, "unbound-wallet-nonce");
    let baseline_credential = baseline_server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {esignet_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": { "proof_type": "jwt", "jwt": baseline_proof }
        }))
        .await;
    baseline_credential.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        baseline_credential.json::<Value>()["error"],
        json!("invalid_token")
    );
    baseline_idp.stop().await;

    // The pre-authorized-code path: the same civil id arrives through the eSignet
    // login leg (the offer/start -> callback -> token chain).
    let preauth_idp = MockIdp::start().await;
    let preauth_token_upstream = MockHttpUpstream::start().await;
    let preauth_tmp = TempDir::new().expect("tempdir");
    let preauth_audit_path = preauth_tmp.path().join("audit.jsonl");
    let preauth_app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        preauth_audit_path.to_str().expect("audit path is UTF-8"),
        &preauth_idp,
        &preauth_token_upstream,
    ))
    .await
    .expect("preauth router builds");
    let preauth_server = TestServer::builder().http_transport().build(preauth_app);

    let (code, pin) = drive_offer_to_code(
        &preauth_server,
        &preauth_token_upstream,
        &preauth_idp,
        "person-1",
    )
    .await;
    let token = redeem_token(&preauth_server, &code, &pin).await;
    token.assert_status_ok();
    let token_body: Value = token.json();
    let access_token = token_body["access_token"]
        .as_str()
        .expect("access token issued")
        .to_string();
    let c_nonce = token_body["c_nonce"]
        .as_str()
        .expect("c_nonce issued")
        .to_string();
    let preauth_proof = sign_oid4vci_proof_without_iss(NOTARY_ISSUER, &c_nonce);
    let preauth_credential = preauth_server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "vct": "http://127.0.0.1:4325/credentials/civil-status",
            "display": [{ "name": "Person is alive" }],
            "credential_signing_alg_values_supported": ["EdDSA"],
            "proof": {
                "proof_type": "jwt",
                "jwt": preauth_proof,
                "subject": "person-1"
            }
        }))
        .await;
    preauth_credential.assert_status_ok();
    let preauth_sd_jwt = preauth_credential.json::<Value>()["credential"]
        .as_str()
        .expect("preauth credential issued")
        .to_string();
    let preauth_audit = credential_issued_audit(&preauth_audit_path);
    assert_eq!(preauth_audit["purposes"], json!(["citizen_subject_access"]));
    preauth_idp.stop().await;

    assert!(
        preauth_audit["target_ref_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("hmac-sha256:")),
        "the transaction audit uses only a keyed subject handle"
    );
    let preauth_payload = decode_sd_jwt_payload(&preauth_sd_jwt);
    assert!(
        !preauth_payload.to_string().contains("person-1"),
        "the raw civil id must not appear in the credential payload"
    );
    let preauth_claim = decode_disclosed_claim(&preauth_sd_jwt, "person-is-alive");
    assert_eq!(preauth_claim["claim_id"], json!("person-is-alive"));
    assert_eq!(preauth_claim["value"], json!(true));
    assert_eq!(preauth_claim["satisfied"], json!(true));
}

#[tokio::test]
pub(super) async fn preauth_callback_and_token_audit_events_carry_only_hashes() {
    set_preauth_env();
    let idp = MockIdp::start().await;
    let token_upstream = MockHttpUpstream::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(preauth_test_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp,
        &token_upstream,
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let (code, pin) = drive_offer_to_code(&server, &token_upstream, &idp, "person-1").await;
    redeem_token(&server, &code, &pin).await.assert_status_ok();

    let audit = std::fs::read_to_string(&audit_path).expect("audit written");
    // The raw code, PIN, civil id, and eSignet code never appear in the audit.
    assert!(
        !audit.contains(&code),
        "raw pre-authorized_code must not be logged"
    );
    assert!(!audit.contains(&pin), "raw tx_code must not be logged");
    assert!(!audit.contains("person-1"), "civil id must not be logged");
    assert!(
        !audit.contains("esignet-code-123"),
        "eSignet code must not be logged"
    );

    // The callback and token audit events are present, hashed-only.
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let callback = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/offer/callback")
                && record["decision"] == json!("preauth_offer_minted")
        })
        .expect("callback audit event exists");
    assert_eq!(callback["status"], json!(200));
    assert_eq!(
        callback["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    let token_event = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/token")
                && record["decision"] == json!("preauth_token_issued")
        })
        .expect("token audit event exists");
    assert_eq!(token_event["status"], json!(200));
    idp.stop().await;
}
