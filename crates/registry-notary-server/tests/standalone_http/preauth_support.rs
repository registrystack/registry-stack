// SPDX-License-Identifier: Apache-2.0

use super::federation::subject_access_oid4vci_config;
use super::support::*;

// Dedicated access-token signing key, distinct from the credential key
// (TEST_ISSUER_JWK). Config validation rejects reusing a credential key.
pub(super) const TEST_ACCESS_TOKEN_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
// eSignet RP client signing key (signs the private_key_jwt client assertion).
pub(super) const TEST_ESIGNET_RP_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"EOLPz23yGd5Ju5e-PYybLE-YyvjgXLhGzS6XgmszzXs","x":"3v5jZ5rAf7KGvcC3zuKh6-ujgtA0ABa4jqmAWXq-S_c","alg":"EdDSA"}"#;
// Test-only 2048-bit RSA private JWK (kty=RSA, alg=RS256) for the eSignet RP
// client when the lab registers the Notary's RP client with an RSA key.
// Generated once with openssl and converted to a JWK; not a production key.
#[cfg(feature = "registry-notary-cel")]
pub(super) const TEST_ESIGNET_RP_RSA_JWK: &str = r#"{"kty":"RSA","kid":"did:web:rp.example#esignet-rp-rsa-key","alg":"RS256","n":"uujuLM_PhTFXueBzTafeFW7O4kJgQnLIzuoHJQgaYDkCBbUYAznt-IZvGkyTTkg4mfolJj47HDlBsSNzzx7bYcFDKdBMoZQwukVX9bhkXVUPT9-fot1jfW0EPrvdJdDQ-5LjQYfk2a2OpKtV5hmBIxoHm_JRU3QOmKU0h1_vKjwStMO0ntaitIL7pSIE0X7Ht4P3edhBc5Vxf_-Ui7wSaN-jAjHCk6HYRY4BTODI-zo5K8yB5JERBqcawsuAIDPTjQ1eIOHxIQsTlsdbmSgqnMldoyZAkjxCyOm9Ad_rpbJ04WDaIhFxyaqHTVUD32cufcZFYxkSJ35zuIlJYgoebw","e":"AQAB","d":"EEvSyFFuFHzS2z_4jaK_ODsrCosi_WgonfHFobLtKcqOpJS_fTiFyQ9fjHl0tnSRistGhekTGkjbs2gV5s8X7ZP-GR0yMTxMa1E0dBYZmhGafipPLtICpKLmpdmXVH66WdTav5HroBcDwtO1b5R1r-vLEgu0j4Qk6aYtyEfTAGmKRzH9fk7crZwaM2MiklIWLaK6Gfior5KDrQhIMGfKZzu78naJ5FyFSHBUW0VvikTg0C8QbRgBuFbQCuOceu4UZhjySJUhugdgzlbnteVRc_VvSvusLL4i7fSeecRIXURSexUjraLifeh1lM_jrD8ZM-o_2Qop2ada12Asll4gkQ","p":"4QhhINnwbq_vuFTQL3Wx980l2eg8yocFS5hsmk7vbqAUbAZVSVOGW_y6ip-uG_c9xpYBvTyZAANUZHpqDyu0frPDdZplJZX2FTMkiHTg4RJQfj8OD0tmL370cGv3RRfO4md4-0E0wxl8Zsv4-PSVrMZCFyIk8TLgLZs1w7bpg0U","q":"1KGH6VP7TkA3hDXTlSL2GPShsGY0Y9P1Kn6mMA8aHIZ690QmeJU2j91oWcCP1AG6LnAp5pvxT0XJJu3OVsQs7OZPiUwAf_RoSdlMtm6xll1FkBKC3AtTLYn0vgHwFPeXa29wZM1khFv_vBdhk47ZgZT0G3f4Y88FHh5EM5EFPCM","dp":"0D332_WyWEu5c4QQ74pjuaP_XgpajzSpgs432ggn6-B5ZYnqzKNdl6xlV7jy3vBKG4Zfb6YvE-MA6saZdRaFviZOP3s0FLcUdYPRT_GQ1Nck498n_KFSm6tJOuu-dBLXIY6NVz19PPpNs7cX3BJCnBMPv-aZ9xaUe7_A3i9bIl0","dq":"gDDudp5aGSAgGEY3TGdqhTsfK_FCTpkf6sG2Qa0pKd9tzRs6MmKLJYrveYTdcYylCZA3wr9raUaCckTWrHrTNvPXKcg3WO0p3rPySt5LlIKhCK4QVMdDG2Zbth4G9y0aDfx-f1dQ7Xdlo6lY-5QYz8XUsabPiqTpyfGnXotk448","qi":"XlLiaiQDLYZXtyR1ixq3dJ1EqnBtHtx75VjpQydmb4yQMtzsQ1JS5xyRgv1gws8u5KVaF3h3CUo6wBrtKBFGIhL9WFnym_8DEECgVF7eLHZ6WNtnIv6Vs7vjO3CAPKG3TrIuaHhY5KXQf0za7criZ9Euai41_ky9_iU6j0Lw5CY"}"#;

pub(super) const NOTARY_ISSUER: &str = "http://127.0.0.1:4325";
pub(super) const NOTARY_AUDIENCE: &str = "registry-notary-citizen";
pub(super) const ESIGNET_RP_CLIENT_ID: &str = "registry-lab-live-client";

pub(super) fn set_preauth_env() {
    set_audit_secret();
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_ACCESS_TOKEN_JWK", TEST_ACCESS_TOKEN_JWK);
    std::env::set_var("TEST_ESIGNET_RP_JWK", TEST_ESIGNET_RP_JWK);
}

pub(super) fn local_jwk_signing_key(private_jwk_env: &str, kid: &str) -> SigningKeyConfig {
    SigningKeyConfig {
        provider: SigningKeyProviderConfig::LocalJwkEnv,
        alg: SD_JWT_VC_SIGNING_ALG.to_string(),
        kid: kid.to_string(),
        status: SigningKeyStatus::Active,
        publish_until_unix_seconds: None,
        private_jwk_env: private_jwk_env.to_string(),
        public_jwk_env: String::new(),
        module_path: String::new(),
        token_label: String::new(),
        pin_env: String::new(),
        key_label: String::new(),
        key_id_hex: String::new(),
        path: String::new(),
        password_env: String::new(),
    }
}

/// A pre-auth-enabled config. eSignet `issuer`/`jwks_uri` point at the MockIdp;
/// the token endpoint points at `token_url` (a wiremock upstream). The
/// access-token signing key is dedicated (distinct from the credential key).
pub(super) fn subject_access_preauth_config(
    base_url: &str,
    audit_path: &str,
    esignet_issuer: &str,
    esignet_jwks_uri: &str,
    esignet_authorize_url: &str,
    esignet_token_url: &str,
) -> StandaloneRegistryNotaryConfig {
    // Reuse the eSignet issuer/jwks as the primary OIDC auth issuer so the
    // credential endpoint still accepts eSignet tokens on the unchanged path.
    let mut config =
        subject_access_oid4vci_config(base_url, audit_path, esignet_issuer, esignet_jwks_uri);
    config.state.storage = registry_notary_core::STATE_STORAGE_IN_MEMORY.to_string();
    // The credential endpoint must be allowed to issue credentials for the
    // pre-auth happy path.
    config.subject_access.allowed_operations.issue_credential = true;
    // The person-is-alive claim must support the SD-JWT VC format for OID4VCI
    // issuance (the base config only lists the claim-result format).
    for claim in config.evidence.claims.iter_mut() {
        if claim.id == "person-is-alive" {
            claim
                .formats
                .push(registry_notary_core::FORMAT_SD_JWT_VC.to_string());
        }
    }
    config
        .subject_access
        .rate_limits
        .tx_code_attempts_per_code_per_minute = 3;
    config
        .subject_access
        .rate_limits
        .invalid_token_per_client_address_per_minute = 50;
    // The Notary RP client id must be an accepted citizen client + audience so a
    // Notary-minted token classifies as subject-access.
    config
        .subject_access
        .citizen_clients
        .allowed_client_ids
        .push(ESIGNET_RP_CLIENT_ID.to_string());
    config
        .oid4vci
        .accepted_token_audiences
        .push(NOTARY_AUDIENCE.to_string());
    if let Some(oidc) = config.auth.oidc.as_mut() {
        oidc.allowed_clients.push(ESIGNET_RP_CLIENT_ID.to_string());
    }

    // Dedicated access-token signing key.
    config.evidence.signing_keys.insert(
        "access-token-key".to_string(),
        local_jwk_signing_key(
            "TEST_ACCESS_TOKEN_JWK",
            "did:web:issuer.example#access-token-key",
        ),
    );
    // eSignet RP client signing key.
    config.evidence.signing_keys.insert(
        "esignet-rp-key".to_string(),
        local_jwk_signing_key("TEST_ESIGNET_RP_JWK", "did:web:rp.example#esignet-rp-key"),
    );

    config.auth.access_token_signing = serde_norway::from_str(&format!(
        r#"
enabled: true
issuer: {NOTARY_ISSUER}
audiences:
  - {NOTARY_AUDIENCE}
allowed_algorithms:
  - EdDSA
token_typ: registry-notary-access+jwt
signing_key_id: access-token-key
access_token_ttl_seconds: 300
"#
    ))
    .expect("access-token signing config parses");

    config.oid4vci.pre_authorized_code = serde_norway::from_str(&format!(
        r#"
enabled: true
tx_code:
  required: true
  input_mode: numeric
  length: 6
esignet:
  client_id: {ESIGNET_RP_CLIENT_ID}
  client_signing_key_id: esignet-rp-key
  redirect_uri: http://127.0.0.1:4325/oid4vci/offer/callback
  authorize_url: {esignet_authorize_url}
  token_url: {esignet_token_url}
  issuer: {esignet_issuer}
  jwks_uri: {esignet_jwks_uri}
  scopes:
    - openid
  login_state_ttl_seconds: 300
  allow_insecure_localhost: true
pre_authorized_code_ttl_seconds: 300
"#
    ))
    .expect("pre-auth config parses");
    config
}

/// Extract a query parameter from a URL.
pub(super) fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

pub(super) fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                } else {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Mint an eSignet id_token bound to the login nonce, with the civil-id claim.
pub(super) fn esignet_id_token(idp: &MockIdp, nonce: &str, national_id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    idp.mint_token(json!({
        "sub": "esignet-citizen-subject",
        "aud": ESIGNET_RP_CLIENT_ID,
        "nonce": nonce,
        "national_id": national_id,
        "scope": "openid subject_access",
        "acr": "urn:example:loa:substantial",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }))
}

pub(super) struct PreauthOfferPage {
    pub(super) code: String,
    pub(super) pin: Option<String>,
    pub(super) offer: Value,
    pub(super) html: String,
}

/// Drive offer/start + offer/callback, returning the rendered offer details.
pub(super) async fn drive_offer_to_page(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> PreauthOfferPage {
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

    let id_token = esignet_id_token(idp, &nonce, national_id);
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
        .expect("offer carries pre-authorized_code")
        .to_string();
    let pin = extract_between(&html, "id=\"tx-code\">", "<");
    PreauthOfferPage {
        code,
        pin,
        offer,
        html,
    }
}

/// Drive offer/start + offer/callback, returning (pre_authorized_code, tx_code).
pub(super) async fn drive_offer_to_code(
    server: &TestServer,
    token_upstream: &MockHttpUpstream,
    idp: &MockIdp,
    national_id: &str,
) -> (String, String) {
    let page = drive_offer_to_page(server, token_upstream, idp, national_id).await;
    let pin = page.pin.expect("offer page shows PIN");
    (page.code, pin)
}

pub(super) fn extract_between(haystack: &str, start: &str, end: &str) -> Option<String> {
    let after = haystack.split_once(start)?.1;
    let value = after.split_once(end)?.0;
    Some(value.to_string())
}

pub(super) async fn redeem_token(
    server: &TestServer,
    code: &str,
    pin: &str,
) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}&tx_code={}",
            urlencode(code),
            urlencode(pin),
        ))
        .await
}

pub(super) async fn redeem_token_without_pin(
    server: &TestServer,
    code: &str,
) -> axum_test::TestResponse {
    server
        .post("/oid4vci/token")
        .add_header("content-type", "application/x-www-form-urlencoded")
        .text(format!(
            "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code={}",
            urlencode(code)
        ))
        .await
}

pub(super) fn urlencode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Decode (without verifying) the JSON claims of a compact JWT's payload.
pub(super) fn jwt_payload(jwt: &str) -> Value {
    let payload_b64 = jwt.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload is base64url");
    serde_json::from_slice(&bytes).expect("payload is JSON")
}

/// Re-sign a pre-authorized-code payload with the configured test access-token
/// key so endpoint tests can exercise authenticated claim-shape variations.
pub(super) fn sign_test_preauthorized_code(payload: Value) -> String {
    sign_ed25519_compact_jwt(
        TEST_ACCESS_TOKEN_JWK,
        registry_notary_core::tokens::PRE_AUTHORIZED_CODE_JWT_TYP,
        "did:web:issuer.example#access-token-key",
        payload,
    )
}

/// Decode (without verifying) the JOSE header of a compact JWT.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn jwt_header(jwt: &str) -> Value {
    let header_b64 = jwt.split('.').next().expect("jwt has a header segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .expect("header is base64url");
    serde_json::from_slice(&bytes).expect("header is JSON")
}

/// Extract a field from an `application/x-www-form-urlencoded` body.
#[cfg(feature = "registry-notary-cel")]
pub(super) fn form_field(body: &str, name: &str) -> Option<String> {
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}
