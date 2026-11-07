//! The portal and wallet endpoints, through the router with real tokens from a
//! test authorization server and real certificates.

mod common;

use std::sync::atomic::Ordering;

use axum_test::{TestResponse, TestServer};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{bearer, Harness, Options, AUDIENCE, HOST, REGISTERED_CLIENT_ID};
use registry_platform_crypto::{
    jws::{parse_compact_jws, JwsLimits},
    PublicJwk, SigningAlgorithm,
};
use registry_platform_testing::assert_json_absent_strings;
use serde_json::{json, Value};

async fn create(server: &TestServer, token: &str, policy: &str) -> TestResponse {
    server
        .post("/v1/sessions")
        .add_header("authorization", bearer(token))
        .json(&json!({ "policy": policy }))
        .await
}

fn request_id_of(request_uri: &str) -> String {
    request_uri
        .rsplit('/')
        .next()
        .expect("a request id")
        .to_owned()
}

async fn status(server: &TestServer, token: &str, reference: &str) -> TestResponse {
    server
        .get(&format!("/v1/sessions/{reference}"))
        .add_header("authorization", bearer(token))
        .await
}

#[tokio::test]
async fn creating_a_session_requires_a_valid_applicant_token() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    let anonymous = server
        .post("/v1/sessions")
        .json(&json!({"policy": "national-id"}))
        .await;
    anonymous.assert_status_unauthorized();
    assert_eq!(anonymous.header("www-authenticate"), "Bearer");

    create(&server, "not-a-token", "national-id")
        .await
        .assert_status_unauthorized();

    // A correctly signed token for this audience without the session scope.
    let unscoped = harness.token("portal", "user-1", "something:else");
    create(&server, &unscoped, "national-id")
        .await
        .assert_status_unauthorized();

    let token = harness.applicant_token("portal", "user-1");
    let created = create(&server, &token, "national-id").await;
    created.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = created.json();
    assert_eq!(body["reference"].as_str().unwrap().len(), 43);
    assert!(body["expiresAt"].as_str().unwrap().ends_with('Z'));
    let request_uri = body["requestUri"].as_str().unwrap();
    assert!(request_uri.starts_with(&format!("https://{HOST}/v1/requests/")));
    let invocation = url::Url::parse(body["walletInvocation"].as_str().unwrap()).unwrap();
    assert_eq!(invocation.scheme(), "openid4vp");
    let pairs: std::collections::BTreeMap<_, _> = invocation.query_pairs().into_owned().collect();
    assert_eq!(pairs["client_id"], format!("x509_san_dns:{HOST}"));
    assert_eq!(pairs["request_uri"], request_uri);
}

#[tokio::test]
async fn a_caller_body_that_repeats_a_member_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let applicant = harness.applicant_token("portal", "user-1");

    // The last `policy` is a real one; a parser that keeps the last member
    // would create the session.
    let repeated = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&applicant))
        .content_type("application/json")
        .bytes(r#"{"policy":"unknown","policy":"national-id"}"#.into())
        .await;
    repeated.assert_status_bad_request();
    create(&server, &applicant, "national-id")
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let issuer = harness.idp.issuer();
    let repeated_read = server
        .post("/v1/presentations/read")
        .add_header("authorization", bearer(&harness.evidence_token()))
        .content_type("application/json")
        .bytes(
            format!(
                r#"{{"reference":"a","reference":"b","principal":{{"issuer":"{issuer}","subject":"user-1"}}}}"#
            )
            .into(),
        )
        .await;
    repeated_read.assert_status_bad_request();
}

#[tokio::test]
async fn an_unknown_policy_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");

    let refused = create(&server, &token, "no-such-policy").await;
    refused.assert_status(axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.header("content-type"), "application/problem+json");
    assert!(service.store().is_empty());
}

#[tokio::test]
async fn a_full_store_refuses_new_sessions_and_keeps_the_live_ones() {
    let harness = Harness::new(&Options {
        maximum_live_sessions: 2,
        ..Options::default()
    })
    .await;
    let (server, _) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");

    let first: Value = create(&server, &token, "national-id").await.json();
    create(&server, &token, "national-id")
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let refused = create(&server, &token, "national-id").await;
    refused.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert!(refused.maybe_header("retry-after").is_some());

    status(&server, &token, first["reference"].as_str().unwrap())
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn expiry_is_enforced_on_read() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");
    let created: Value = create(&server, &token, "national-id").await.json();
    let reference = created["reference"].as_str().unwrap();
    let request_id = request_id_of(created["requestUri"].as_str().unwrap());

    status(&server, &token, reference).await.assert_status_ok();
    server
        .get(&format!("/v1/requests/{request_id}"))
        .await
        .assert_status_ok();

    harness.time.fetch_add(300, Ordering::SeqCst);
    // The session is still in memory: cleanup has not run.
    assert_eq!(service.store().len(), 1);
    status(&server, &token, reference)
        .await
        .assert_status_not_found();
    server
        .get(&format!("/v1/requests/{request_id}"))
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn status_is_visible_only_to_the_creating_principal() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let creator = harness.applicant_token("portal", "user-1");
    let created: Value = create(&server, &creator, "national-id").await.json();
    let reference = created["reference"].as_str().unwrap();

    let own = status(&server, &creator, reference).await;
    own.assert_status_ok();
    let own: Value = own.json();
    assert_eq!(own["status"], "pending");
    assert_eq!(own["policy"], "national-id");

    // Same client, different subject; and a different client.
    let other_subject = harness.applicant_token("portal", "user-2");
    let other_client = harness.applicant_token("portal-b", "user-1");
    let unknown = status(&server, &creator, "A".repeat(43).as_str()).await;
    unknown.assert_status_not_found();
    for token in [&other_subject, &other_client] {
        let refused = status(&server, token, reference).await;
        refused.assert_status_not_found();
        assert_eq!(
            refused.text(),
            unknown.text(),
            "not-yours must read as unknown"
        );
    }

    server
        .get(&format!("/v1/sessions/{reference}"))
        .await
        .assert_status_unauthorized();
}

struct Fetched {
    jws: String,
    session_key: serde_json::Map<String, Value>,
    nonce: String,
    state: String,
    expires_at: u64,
    reference: String,
    request_id: String,
}

async fn fetch(
    harness: &Harness,
    server: &TestServer,
    service: &registry_evidence_oid4vp::service::VerifierService,
    policy: &str,
) -> Fetched {
    let token = harness.applicant_token("portal", "user-1");
    let created: Value = create(server, &token, policy).await.json();
    let reference = created["reference"].as_str().unwrap().to_owned();
    let request_id = request_id_of(created["requestUri"].as_str().unwrap());
    let response = server.get(&format!("/v1/requests/{request_id}")).await;
    response.assert_status_ok();
    assert_eq!(
        response.header("content-type"),
        "application/oauth-authz-req+jwt"
    );
    let (session_key, nonce, state, expires_at) = service
        .store()
        .with_by_reference(&reference, |session| {
            (
                session.encryption_key.public_jwk(),
                session.nonce.clone(),
                session.state.clone(),
                session.expires_at,
            )
        })
        .expect("the session is live");
    Fetched {
        jws: response.text(),
        session_key,
        nonce,
        state,
        expires_at,
        reference,
        request_id,
    }
}

fn verified_claims(harness: &Harness, jws: &str) -> (serde_json::Map<String, Value>, Value) {
    let parsed = parse_compact_jws(jws, &JwsLimits::default()).expect("a compact JWS");
    let header = parsed.header().clone();
    let payload = parsed
        .verify(&harness.keys.public_jwk, &[SigningAlgorithm::Es256])
        .expect("signed by the leaf key");
    (header, serde_json::from_slice(payload).unwrap())
}

#[tokio::test]
async fn the_request_object_is_signed_under_the_x509_san_dns_identifier() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "national-id").await;
    let (header, claims) = verified_claims(&harness, &fetched.jws);

    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(header["alg"], "ES256");
    let x5c: Vec<&str> = header["x5c"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect();
    assert_eq!(x5c.len(), 1);
    assert_eq!(STANDARD.decode(x5c[0]).unwrap(), harness.keys.leaf_der);

    assert_eq!(claims["client_id"], format!("x509_san_dns:{HOST}"));
    assert_eq!(claims["response_type"], "vp_token");
    assert_eq!(claims["response_mode"], "direct_post.jwt");
    assert_eq!(
        claims["response_uri"],
        format!("https://{HOST}/v1/responses/{}", fetched.request_id)
    );
    assert_eq!(claims["nonce"], fetched.nonce);
    assert_eq!(claims["state"], fetched.state);
    assert_eq!(claims["aud"], "https://self-issued.me/v2");
    assert!(claims["iat"].as_u64().unwrap() <= claims["exp"].as_u64().unwrap());
    assert!(claims["exp"].as_u64().unwrap() <= fetched.expires_at);
    assert_ne!(fetched.request_id, fetched.reference);
}

#[tokio::test]
async fn the_request_object_is_signed_under_the_x509_hash_identifier() {
    let harness = Harness::new(&Options {
        client_identifier: "x509-hash",
        sans: vec!["unrelated.example.net".to_owned()],
        ..Options::default()
    })
    .await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "national-id").await;
    let (_, claims) = verified_claims(&harness, &fetched.jws);

    let expected = registry_platform_x509::x509_hash(&harness.keys.leaf_der);
    assert_eq!(claims["client_id"], format!("x509_hash:{expected}"));
    assert!(claims["exp"].as_u64().unwrap() <= fetched.expires_at);
}

#[tokio::test]
async fn dcql_omits_claims_when_the_policy_asks_for_none() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "possession-check").await;
    let (_, claims) = verified_claims(&harness, &fetched.jws);
    assert_eq!(
        claims["dcql_query"],
        json!({"credentials": [{
            "id": "possession",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["https://credentials.example.org/national-id"]},
        }]})
    );
}

#[tokio::test]
async fn dcql_carries_trusted_authorities_only_when_the_policy_has_them() {
    let without = Harness::new(&Options::default()).await;
    let (server, service) = without.server().await;
    let fetched = fetch(&without, &server, &service, "national-id").await;
    let (_, claims) = verified_claims(&without, &fetched.jws);
    assert_eq!(
        claims["dcql_query"],
        json!({"credentials": [{
            "id": "national_id",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["https://credentials.example.org/national-id"]},
            "claims": [{"path": ["given_name"]}, {"path": ["address", "locality"]}],
        }]})
    );

    let with = Harness::new(&Options {
        trusted_authorities: true,
        ..Options::default()
    })
    .await;
    let (server, service) = with.server().await;
    let fetched = fetch(&with, &server, &service, "national-id").await;
    let (_, claims) = verified_claims(&with, &fetched.jws);
    assert_eq!(
        claims["dcql_query"]["credentials"][0]["trusted_authorities"],
        json!([{"type": "aki", "values": ["c2lnbmluZy1rZXktaWRlbnRpZmllcg"]}])
    );
}

#[tokio::test]
async fn client_metadata_advertises_the_session_key_and_the_policy_encryption() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;

    let fetched = fetch(&harness, &server, &service, "national-id").await;
    let (_, claims) = verified_claims(&harness, &fetched.jws);
    let metadata = &claims["client_metadata"];
    let keys = metadata["jwks"]["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], Value::Object(fetched.session_key.clone()));
    assert_eq!(keys[0]["use"], "enc");
    assert_eq!(keys[0]["alg"], "ECDH-ES");
    assert!(keys[0]["kid"].is_string());
    assert!(keys[0].get("d").is_none());
    assert_eq!(
        metadata["encrypted_response_enc_values_supported"],
        json!(["A128GCM", "A256GCM"])
    );
    assert_eq!(
        metadata["vp_formats_supported"],
        json!({"dc+sd-jwt": {
            "sd-jwt_alg_values": ["ES256", "EdDSA"],
            "kb-jwt_alg_values": ["ES256", "EdDSA"],
        }})
    );

    let narrow = fetch(&harness, &server, &service, "age-check").await;
    let (_, claims) = verified_claims(&harness, &narrow.jws);
    assert_eq!(
        claims["client_metadata"]["encrypted_response_enc_values_supported"],
        json!(["A256GCM"])
    );
    assert_ne!(
        claims["client_metadata"]["jwks"]["keys"][0], keys[0],
        "each session has its own key"
    );
}

#[tokio::test]
async fn the_audit_journal_records_both_operations_and_leaks_no_session_secret() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "national-id").await;

    let journal = harness.audit_journal();
    let entries: Vec<Value> = journal
        .lines()
        .map(|line| serde_json::from_str(line).expect("each entry is JSON"))
        .collect();
    assert!(!entries.is_empty());
    let text = journal.as_str();
    assert!(text.contains("session_creation"), "{text}");
    assert!(text.contains("request_fetch"), "{text}");
    assert!(text.contains("national-id"), "{text}");
    assert!(text.contains("sha256:"), "{text}");

    let jwk_parts: Vec<String> = ["x", "y", "kid"]
        .iter()
        .map(|member| fetched.session_key[*member].as_str().unwrap().to_owned())
        .collect();
    let mut forbidden = vec![
        fetched.reference.clone(),
        fetched.request_id.clone(),
        fetched.nonce.clone(),
        fetched.state.clone(),
        fetched.jws.clone(),
        harness.applicant_token("portal", "user-1"),
    ];
    forbidden.extend(jwk_parts);
    for entry in &entries {
        assert_json_absent_strings(entry, &forbidden).expect("no secret reaches the journal");
    }
    assert!(!text.contains("user-1"), "principals are pseudonymized");
}

#[tokio::test]
async fn the_wallet_endpoint_and_session_creation_are_rate_limited() {
    let harness = Harness::new(&Options {
        wallet_request_burst: 2,
        session_creation_burst: 1,
        ..Options::default()
    })
    .await;
    let (server, _) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");

    create(&server, &token, "national-id")
        .await
        .assert_status(axum::http::StatusCode::CREATED);
    let limited = create(&server, &token, "national-id").await;
    limited.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.maybe_header("retry-after").is_some());
    // Another principal has its own budget.
    let other = harness.applicant_token("portal-b", "user-9");
    create(&server, &other, "national-id")
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    for _ in 0..2 {
        server
            .get("/v1/requests/unknown")
            .await
            .assert_status_not_found();
    }
    let limited = server.get("/v1/requests/unknown").await;
    limited.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.maybe_header("retry-after").is_some());
}

#[tokio::test]
async fn operational_routes_answer_and_every_response_carries_security_headers() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    server.get("/health").await.assert_status_ok();
    server.get("/ready").await.assert_status_ok();
    let unknown = server.get("/nope").await;
    unknown.assert_status_not_found();
    assert_eq!(unknown.header("x-content-type-options"), "nosniff");
    assert!(unknown.maybe_header("content-security-policy").is_some());

    let token = harness.applicant_token("portal", "user-1");
    let oversized = server
        .post("/v1/sessions")
        .add_header("authorization", bearer(&token))
        .text("x".repeat(64 * 1024))
        .await;
    assert!(oversized.status_code().is_client_error());
    let _ = AUDIENCE;
}

const DID: &str = "did:web:verifier.example.org";
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode base58btc by long arithmetic, independently of the service's
/// encoder.
fn base58_decode(text: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for character in text.bytes() {
        let mut carry = BASE58_ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .expect("a base58btc character");
        for byte in &mut bytes {
            carry += usize::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    bytes.extend(text.bytes().take_while(|c| *c == b'1').map(|_| 0));
    bytes.reverse();
    bytes
}

fn ed25519_jwk(x: &[u8]) -> PublicJwk {
    PublicJwk::parse(
        &json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
        })
        .to_string(),
    )
    .expect("an Ed25519 public JWK")
}

fn verified_with(jws: &str, key: &PublicJwk) -> (serde_json::Map<String, Value>, Value) {
    let parsed = parse_compact_jws(jws, &JwsLimits::default()).expect("a compact JWS");
    let header = parsed.header().clone();
    let payload = parsed
        .verify(key, &[SigningAlgorithm::EdDsa])
        .expect("signed by the published key");
    (header, serde_json::from_slice(payload).unwrap())
}

#[test]
fn the_test_base58_decoder_matches_a_known_vector() {
    assert_eq!(base58_decode("2NEpo7TZRRrLZSi2U"), b"Hello World!");
    assert_eq!(base58_decode("11z"), vec![0, 0, 57]);
}

#[tokio::test]
async fn the_did_document_has_the_shape_inji_resolves() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    // No credentials: a wallet fetches it anonymously.
    let response = server.get("/.well-known/did.json").await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "application/json");
    let cache = response.header("cache-control");
    assert!(cache.to_str().unwrap().contains("max-age="), "{cache:?}");
    assert!(!cache.to_str().unwrap().contains("no-store"), "{cache:?}");

    let thumbprint = harness.keys.did_public.jkt().unwrap();
    let method_id = format!("{DID}#{thumbprint}");
    let document: Value = response.json();
    let multibase = document["verificationMethod"][0]["publicKeyMultibase"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        document,
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": DID,
            "verificationMethod": [{
                "id": method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": DID,
                "publicKeyMultibase": multibase,
            }],
            "authentication": [method_id],
            "assertionMethod": [method_id],
        })
    );
    // `z`, then base58btc of the Ed25519 multicodec prefix and the 32-byte key.
    let decoded = base58_decode(multibase.strip_prefix('z').expect("a z multibase"));
    assert_eq!(decoded[..2], [0xed, 0x01]);
    let expected_x = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(harness.keys.did_public.x.as_deref().unwrap())
        .unwrap();
    assert_eq!(decoded[2..], expected_x[..]);
}

#[tokio::test]
async fn the_request_object_is_signed_under_the_did_web_identifier() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "inji-did-id").await;

    // The key a wallet resolves: the verification method whose id is the
    // request's `kid`, read back from the served document.
    let document: Value = server.get("/.well-known/did.json").await.json();
    let (header, _) = {
        let parsed = parse_compact_jws(&fetched.jws, &JwsLimits::default()).unwrap();
        (parsed.header().clone(), ())
    };
    let kid = header["kid"].as_str().unwrap();
    let method = document["verificationMethod"]
        .as_array()
        .unwrap()
        .iter()
        .find(|method| method["id"] == kid)
        .expect("the document names the request's kid");
    let multibase = method["publicKeyMultibase"].as_str().unwrap();
    let key = ed25519_jwk(&base58_decode(&multibase[1..])[2..]);

    let (header, claims) = verified_with(&fetched.jws, &key);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(
        header["kid"],
        format!("{DID}#{}", harness.keys.did_public.jkt().unwrap())
    );
    assert!(header.get("x5c").is_none());
    assert_eq!(
        claims["client_id"],
        format!("decentralized_identifier:{DID}")
    );
    assert_eq!(claims["response_type"], "vp_token");
    assert_eq!(claims["response_mode"], "direct_post.jwt");
    assert_eq!(claims["nonce"], fetched.nonce);
    assert_eq!(claims["state"], fetched.state);
    assert_eq!(
        claims["response_uri"],
        format!("https://{HOST}/v1/responses/{}", fetched.request_id)
    );
}

#[tokio::test]
async fn the_request_object_is_signed_under_the_pre_registered_identifier() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "inji-registered-id").await;

    let response = server.get("/v1/jwks").await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "application/json");
    let jwks: Value = response.json();
    let thumbprint = harness.keys.registered_public.jkt().unwrap();
    // Every EdDSA identifier is published; a wallet selects by `kid`.
    let published = jwks["keys"].as_array().unwrap();
    assert_eq!(published.len(), 2);
    let entry = published
        .iter()
        .find(|entry| entry["kid"] == thumbprint)
        .expect("the pre-registered key is published under its thumbprint");
    assert_eq!(
        *entry,
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": harness.keys.registered_public.x,
            "kid": thumbprint,
            "use": "sig",
            "alg": "EdDSA",
        })
    );
    assert!(entry.get("d").is_none());
    let key = PublicJwk::parse(&entry.to_string()).unwrap();

    let (header, claims) = verified_with(&fetched.jws, &key);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(header["kid"], thumbprint);
    assert!(header.get("x5c").is_none());
    assert_eq!(claims["client_id"], REGISTERED_CLIENT_ID);
    assert_eq!(claims["response_mode"], "direct_post.jwt");
    assert_eq!(claims["nonce"], fetched.nonce);
}

#[tokio::test]
async fn the_identifier_documents_are_served_only_when_an_identifier_needs_them() {
    let harness = Harness::new(&Options {
        inji: false,
        ..Options::default()
    })
    .await;
    let (server, _) = harness.server().await;
    server
        .get("/.well-known/did.json")
        .await
        .assert_status_not_found();
    server.get("/v1/jwks").await.assert_status_not_found();
}

#[tokio::test]
async fn the_wallet_invocation_names_the_policys_client_identifier() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");
    for (policy, expected) in [
        ("national-id", format!("x509_san_dns:{HOST}")),
        ("inji-did-id", format!("decentralized_identifier:{DID}")),
        ("inji-registered-id", REGISTERED_CLIENT_ID.to_owned()),
    ] {
        let created: Value = create(&server, &token, policy).await.json();
        let invocation = created["walletInvocation"].as_str().unwrap();
        let query = invocation
            .strip_prefix("openid4vp://authorize?")
            .expect("the openid4vp scheme");
        let client_id = url::form_urlencoded::parse(query.as_bytes())
            .find(|(name, _)| name == "client_id")
            .map(|(_, value)| value.into_owned())
            .expect("a client_id parameter");
        assert_eq!(client_id, expected, "{policy}");
    }
}

#[tokio::test]
async fn an_inji_shaped_request_asks_in_the_form_inji_accepts() {
    let harness = Harness::new(&Options::default()).await;
    let (server, service) = harness.server().await;
    let fetched = fetch(&harness, &server, &service, "inji-did-id").await;
    let document: Value = server.get("/.well-known/did.json").await.json();
    let multibase = document["verificationMethod"][0]["publicKeyMultibase"]
        .as_str()
        .unwrap();
    let key = ed25519_jwk(&base58_decode(&multibase[1..])[2..]);
    let (_, claims) = verified_with(&fetched.jws, &key);

    assert_eq!(
        claims["dcql_query"],
        json!({"credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["https://credentials.example.org/national-id"]},
            "claims": [{"path": ["given_name"]}],
        }]})
    );
    assert!(claims["dcql_query"]["credentials"][0]
        .get("trusted_authorities")
        .is_none());
    let metadata = &claims["client_metadata"];
    assert_eq!(
        metadata["encrypted_response_enc_values_supported"],
        json!(["A256GCM"])
    );
    assert!(metadata["vp_formats_supported"]["dc+sd-jwt"].is_object());
    let encryption_key = &metadata["jwks"]["keys"][0];
    assert_eq!(encryption_key["alg"], "ECDH-ES");
    assert_eq!(encryption_key["use"], "enc");
    assert!(encryption_key["kid"]
        .as_str()
        .is_some_and(|kid| !kid.is_empty()));
}

/// The published contract with `component` as the schema to check against.
fn contract_validator(component: &str) -> jsonschema::JSONSchema {
    let document = registry_evidence_oid4vp::contracts::openapi_document();
    let schema = json!({
        "$ref": format!("#/components/schemas/{component}"),
        "components": document["components"],
    });
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("the contract schema compiles")
}

fn assert_valid(component: &str, instance: &Value) {
    let validator = contract_validator(component);
    let result = validator.validate(instance);
    if let Err(errors) = result {
        let errors: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("{component} does not describe {instance}: {errors:?}");
    }
}

#[tokio::test]
async fn every_published_route_is_served_and_every_served_route_is_published() {
    use registry_evidence_oid4vp::contracts::{openapi_document, ROUTES};

    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let document = openapi_document();
    for path in ROUTES {
        let method = document["paths"][path]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let concrete = path
            .replace("{reference}", "unknown")
            .replace("{request_id}", "unknown");
        let response = match method.as_str() {
            "get" => server.get(&concrete).await,
            "post" => server.post(&concrete).await,
            other => panic!("unexpected method {other}"),
        };
        // A route the router does not know answers 404 `not-found` or 405.
        let body = response.text();
        assert_ne!(response.status_code().as_u16(), 405, "{path}");
        assert!(
            !body.contains("problems/registry-evidence-oid4vp/not-found"),
            "{path}: {body}"
        );
    }
    // A route the contract does not publish is not served.
    server
        .get("/v1/unpublished")
        .await
        .assert_status_not_found();
}

#[tokio::test]
async fn served_bodies_match_the_published_schemas() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;

    assert_valid("HealthResponse", &server.get("/health").await.json());
    assert_valid("ReadinessResponse", &server.get("/ready").await.json());
    assert_valid(
        "DidDocument",
        &server.get("/.well-known/did.json").await.json(),
    );
    assert_valid("Jwks", &server.get("/v1/jwks").await.json());

    let token = harness.applicant_token("portal", "user-1");
    let created = create(&server, &token, "national-id").await;
    created.assert_status(axum::http::StatusCode::CREATED);
    let created: Value = created.json();
    assert_valid("CreateSessionResponse", &created);
    let reference = created["reference"].as_str().unwrap();
    assert_valid(
        "SessionStatus",
        &status(&server, &token, reference).await.json(),
    );
}

/// Unix seconds of 2091-01-01, after the harness certificate's `notAfter`.
const AFTER_CERTIFICATE_EXPIRY: u64 = 3_818_448_000;

#[tokio::test]
async fn readiness_fails_once_the_client_identifier_certificate_has_expired() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    server.get("/ready").await.assert_status_ok();

    harness
        .time
        .store(AFTER_CERTIFICATE_EXPIRY, Ordering::SeqCst);
    let ready = server.get("/ready").await;
    ready.assert_status(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.json::<Value>(), json!({"status": "not_ready"}));
    // Liveness is unaffected: the process is healthy, the certificate is not.
    server.get("/health").await.assert_status_ok();
}

#[tokio::test]
async fn readiness_stays_ready_inside_the_certificate_validity() {
    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    // Well before the certificate's end.
    harness
        .time
        .store(AFTER_CERTIFICATE_EXPIRY - 100_000_000, Ordering::SeqCst);
    server.get("/ready").await.assert_status_ok();
}

#[tokio::test]
async fn every_problem_the_service_answers_is_in_the_closed_vocabulary() {
    use registry_evidence_oid4vp::problem::{ProblemCode, PROBLEM_TYPE_BASE};

    let harness = Harness::new(&Options::default()).await;
    let (server, _) = harness.server().await;
    let token = harness.applicant_token("portal", "user-1");
    let answers = [
        server.get("/nope").await,
        server.post("/health").await,
        server.get("/v1/requests/unknown").await,
        server.post("/v1/sessions").await,
        server
            .post("/v1/sessions")
            .add_header("authorization", bearer(&token))
            .json(&json!({ "policy": "no-such-policy" }))
            .await,
        server
            .get(&format!("/v1/sessions/{}", "A".repeat(43)))
            .add_header("authorization", bearer(&token))
            .await,
    ];
    let mut seen = Vec::new();
    for answer in answers {
        let body: Value = answer.json();
        let uri = body["type"].as_str().expect("a problem type").to_owned();
        let code = uri
            .strip_prefix(PROBLEM_TYPE_BASE)
            .unwrap_or_else(|| panic!("{uri} is outside the service's problem base"));
        let problem = ProblemCode::from_code(code)
            .unwrap_or_else(|| panic!("{code} is not in ProblemCode::ALL"));
        assert_eq!(body["title"], problem.title());
        assert_eq!(answer.status_code().as_u16(), problem.http_status());
        seen.push(problem);
    }
    assert!(seen.len() >= 5, "{seen:?}");
}
