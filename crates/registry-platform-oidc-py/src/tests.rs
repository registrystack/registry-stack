use std::time::{SystemTime, UNIX_EPOCH};

use oidc_core::{parse_static_jwks, JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{fixtures, sign_ed25519_compact_jwt_with_key};
use serde_json::json;

use super::*;

const ISSUER: &str = "https://issuer.example";
const RESOURCE: &str = "urn:registry:service";
const CLIENT: &str = "service-client";

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the test clock is after the Unix epoch")
            .as_secs(),
    )
    .expect("the test clock fits in i64")
}

fn test_policy() -> Policy {
    policy(
        ISSUER.to_owned(),
        RESOURCE.to_owned(),
        CLIENT.to_owned(),
        "EdDSA",
        "at+jwt".to_owned(),
        600,
        3_600,
        0,
        vec!["registry_principal".to_owned(), "actor_kind".to_owned()],
    )
    .expect("test policy")
}

fn verifier() -> AccessTokenVerifier {
    let (_, public) = fixtures::ed25519_pair();
    let jwks = parse_static_jwks(
        serde_json::to_vec(&json!({"keys": [public]}))
            .expect("serialize public JWKS")
            .as_slice(),
    )
    .expect("parse public JWKS");
    AccessTokenVerifier::from_parts(
        test_policy(),
        Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())),
    )
    .expect("build verifier")
}

fn claims(audience: Value) -> Value {
    let now = now();
    json!({
        "iss": ISSUER,
        "aud": audience,
        "sub": "subject-1",
        "azp": CLIENT,
        "exp": now + 300,
        "iat": now,
        "nbf": now - 1,
        "scope": "command:submit job:read",
        "registry_principal": "principal-1",
        "actor_kind": "service",
        "unselected": "must-not-cross-the-binding",
    })
}

fn sign(typ: &str, claims: Value) -> String {
    let (private, _) = fixtures::ed25519_pair();
    sign_ed25519_compact_jwt_with_key(&private, typ, "registry-platform-testing-ed25519-1", claims)
}

#[test]
fn configuration_requires_one_exact_asymmetric_algorithm() {
    assert!(algorithm("RS256").is_ok());
    assert!(algorithm("HS256").is_err());
    assert!(algorithm("rs256").is_err());
    assert_eq!(
        ensure_public_static_jwks(
            format!(r#"{{"keys":[{}]}}"#, fixtures::ED25519_PRIVATE_JWK).as_bytes()
        ),
        Err(FailureKind::Configuration)
    );
}

#[test]
fn a_valid_access_token_returns_only_bounded_selected_claims() {
    let verifier = verifier();
    let token = sign("at+jwt", claims(json!(RESOURCE)));
    let verified = verifier.verify_access(&token).expect("token verifies");
    assert_eq!(verified.kind, TokenKind::Access);
    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.audiences, vec![RESOURCE.to_owned()]);
    assert_eq!(verified.subject, "subject-1");
    assert_eq!(verified.client_id, CLIENT);
    assert_eq!(
        verified.scopes,
        vec!["command:submit".to_owned(), "job:read".to_owned()]
    );
    assert_eq!(
        verified.claims,
        BTreeMap::from([
            ("actor_kind".to_owned(), "service".to_owned()),
            ("registry_principal".to_owned(), "principal-1".to_owned()),
        ])
    );
    assert!(!verified.claims.contains_key("unselected"));
}

#[test]
fn conflicting_client_claims_and_extra_audiences_are_refused() {
    let verifier = verifier();
    let mut conflict = claims(json!(RESOURCE));
    conflict["client_id"] = json!("other-client");
    let token = sign("at+jwt", conflict);
    assert_eq!(
        verifier
            .verify_access(&token)
            .expect_err("conflict refuses"),
        FailureKind::Verification
    );

    let token = sign("at+jwt", claims(json!([RESOURCE, "urn:registry:other"])));
    assert_eq!(
        verifier
            .verify_access(&token)
            .expect_err("extra audience refuses"),
        FailureKind::Verification
    );
}

#[test]
fn related_id_token_requires_the_expected_nonce_and_client_audience() {
    let verifier = verifier();
    let mut id_claims = claims(json!(CLIENT));
    id_claims["nonce"] = json!("pending-nonce");
    id_claims
        .as_object_mut()
        .expect("claims are an object")
        .remove("scope");
    id_claims
        .as_object_mut()
        .expect("claims are an object")
        .remove("azp");
    let token = sign("JWT", id_claims);
    let verified = verifier
        .verify_id(&token, "pending-nonce")
        .expect("ID token verifies");
    assert_eq!(verified.kind, TokenKind::Id);
    assert_eq!(verified.audiences, vec![CLIENT.to_owned()]);
    assert_eq!(
        verifier
            .verify_id(&token, "different-nonce")
            .expect_err("wrong nonce refuses"),
        FailureKind::Verification
    );
}

#[test]
fn token_and_output_bounds_fail_closed() {
    let policy = test_policy();
    assert_eq!(
        bounded_token(&"x".repeat(MAXIMUM_TOKEN_BYTES + 1)),
        Err(FailureKind::Verification)
    );
    assert!(checked_claim_names(vec!["scope".to_owned()]).is_err());
    let mut extra = serde_json::Map::new();
    extra.insert(
        "registry_principal".to_owned(),
        json!("x".repeat(MAXIMUM_CLAIM_VALUE_BYTES + 1)),
    );
    assert_eq!(
        selected_claims(&extra, &policy.claim_names),
        Err(FailureKind::Verification)
    );
}
