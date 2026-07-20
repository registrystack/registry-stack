// SPDX-License-Identifier: Apache-2.0
//! SD-JWT VC verifier compatibility harness.
//!
//! Verifies committed golden fixtures against the `verify_sd_jwt_vc` path in
//! `registry-notary-client`. Each test is self-contained: it reads a fixture
//! file and the issuer JWKS from `tests/fixtures/sd_jwt_vc/`, then calls the
//! verifier with a deterministic clock that matches the fixture timestamps.
//!
//! Run the harness with:
//!   cargo nextest run -p registry-notary-server sd_jwt_vc_verifier_compat
//! or:
//!   cargo test -p registry-notary-server --test sd_jwt_vc_verifier_compat
//!
//! The harness requires no secret material and no network access.
//! Fixtures are pre-generated synthetic material. Regenerate them with:
//!   cargo run -p xtask -- gen-sd-jwt-vc-fixtures
//! or regenerate only the deterministic 1.0 algorithm fixtures with:
//!   cargo run -p xtask -- gen-oid4vci-algorithm-fixtures

use std::path::Path;
use std::time::Duration;

use registry_notary_client::verifier::verify_sd_jwt_vc;
use registry_notary_client::{HolderBindingPolicy, VerifyOptions};
use registry_platform_crypto::{did_jwk_from_public_jwk, PrivateJwk};
use registry_platform_oid4vci::{
    validate_proof_jwt, ProofError, ProofIssuerPolicy, ProofValidationPolicy,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Constants that match the fixture generator in xtask/src/main.rs.
// If you change the generator, update these constants too.
// ---------------------------------------------------------------------------

const ISSUER: &str = "did:web:fixture.test";
const VCT: &str = "https://fixture.test/credentials/registry-witness/v1";
// Fixed clock: 2024-01-15T00:00:10Z (10 seconds after IAT so exp check passes).
const NOW_UNIX: i64 = 1_705_276_810;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fixture_dir() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is crates/registry-notary-server/
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent() // crates/
        .and_then(Path::parent) // workspace root
        .expect("workspace root exists")
        .join("products/notary/tests/fixtures/sd_jwt_vc")
}

fn read_fixture(name: &str) -> String {
    let path = fixture_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("fixture {name} unreadable at {}: {e}", path.display()))
        .trim()
        .to_string()
}

fn read_fixture_json(name: &str) -> Value {
    let content = read_fixture(name);
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("fixture {name} is not valid JSON: {e}"))
}

fn jwks() -> Value {
    read_fixture_json("issuer-jwks.json")
}

fn meta() -> Value {
    read_fixture_json("meta.json")
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(NOW_UNIX).expect("test timestamp")
}

fn base_options() -> VerifyOptions {
    VerifyOptions::new(ISSUER).expected_vct(VCT).now(now())
}

// ---------------------------------------------------------------------------
// Positive fixtures
// ---------------------------------------------------------------------------

#[test]
fn valid_credential_verifies_end_to_end() {
    let compact = read_fixture("valid.sd-jwt");
    let result =
        verify_sd_jwt_vc(&compact, &jwks(), &base_options()).expect("valid fixture must verify");

    let meta = meta();
    assert_eq!(result.issuer, ISSUER);
    assert_eq!(result.vct, VCT);
    assert_eq!(result.algorithm, "EdDSA");
    assert_eq!(
        result.key_id,
        meta["key_id"].as_str().expect("key_id in meta")
    );
    // valid.sd-jwt was issued with claim_a and claim_b.
    assert_eq!(result.disclosure_count, 2);
    assert!(
        result.holder_key_id.is_none(),
        "no holder binding in valid.sd-jwt"
    );
    assert!(result.expires_at > result.issued_at);
}

#[test]
fn valid_holder_bound_credential_verifies_with_required_kid_policy() {
    let compact = read_fixture("valid-holder-bound.sd-jwt");
    let meta = meta();
    let holder_did = meta["holder_did"]
        .as_str()
        .expect("holder_did in meta")
        .to_string();

    let options =
        base_options().holder_binding(HolderBindingPolicy::RequiredKid(holder_did.clone()));
    let result = verify_sd_jwt_vc(&compact, &jwks(), &options)
        .expect("holder-bound fixture must verify with RequiredKid policy");

    assert_eq!(result.issuer, ISSUER);
    assert_eq!(result.vct, VCT);
    assert_eq!(
        result.holder_key_id.as_deref(),
        Some(holder_did.as_str()),
        "holder_key_id must match the cnf.kid in the credential"
    );
}

#[test]
fn es256_credential_verifies_end_to_end_with_explicit_algorithm_policy() {
    let compact = read_fixture("valid-es256.sd-jwt");
    let meta = meta();
    let holder_did = meta["holder_did"]
        .as_str()
        .expect("holder_did in meta")
        .to_string();
    let options = base_options()
        .accepted_algorithms(["ES256"])
        .holder_binding(HolderBindingPolicy::RequiredKid(holder_did.clone()));

    let result = verify_sd_jwt_vc(&compact, &jwks(), &options)
        .expect("ES256 issuer fixture must verify when explicitly accepted");

    assert_eq!(result.algorithm, "ES256");
    assert_eq!(
        result.key_id,
        meta["es256_key_id"].as_str().expect("es256_key_id in meta")
    );
    assert_eq!(result.holder_key_id.as_deref(), Some(holder_did.as_str()));
    assert_eq!(result.disclosure_count, 0);
}

#[test]
fn es256_credential_is_not_silently_enabled_by_the_default_verifier_policy() {
    let err = verify_sd_jwt_vc(
        &read_fixture("valid-es256.sd-jwt"),
        &jwks(),
        &base_options(),
    )
    .expect_err("ES256 must require an explicit verifier allow-list");

    assert_eq!(err.code(), "algorithm.disallowed");
}

#[test]
fn oid4vci_algorithm_profile_is_exact_and_narrow() {
    let profile = read_fixture_json("algorithm-profile.json");
    let configurations = &profile["credential_configurations"];

    assert_eq!(
        configurations["fixture_eddsa"],
        serde_json::json!({
            "credential_signing_alg_values_supported": ["EdDSA"],
            "proof_signing_alg_values_supported": ["EdDSA"],
            "cryptographic_binding_methods_supported": ["did:jwk"],
            "fixture": "valid-holder-bound.sd-jwt",
            "private_jwk_fixture": "issuer-eddsa-private.test.jwk.json"
        })
    );
    assert_eq!(
        configurations["fixture_es256"],
        serde_json::json!({
            "credential_signing_alg_values_supported": ["ES256"],
            "proof_signing_alg_values_supported": ["EdDSA"],
            "cryptographic_binding_methods_supported": ["did:jwk"],
            "fixture": "valid-es256.sd-jwt",
            "private_jwk_fixture": "issuer-es256-private.test.jwk.json"
        })
    );
    assert_eq!(
        profile["holder_proof"],
        serde_json::json!({
            "signing_alg_values_supported": ["EdDSA"],
            "cryptographic_binding_methods_supported": ["did:jwk"],
            "fixture": "holder-proof-eddsa.jwt",
            "private_jwk_fixture": "holder-eddsa-private.test.jwk.json",
            "unsupported_fixture": "holder-proof-es256-unsupported.jwt"
        })
    );
    assert_eq!(
        configurations
            .as_object()
            .expect("credential_configurations is an object")
            .len(),
        2,
        "fixture profile must not imply additional credential algorithms"
    );
}

#[test]
fn algorithm_private_key_fixtures_match_public_metadata() {
    let profile = read_fixture_json("algorithm-profile.json");
    let jwks = jwks();
    let public_keys = jwks["keys"].as_array().expect("JWKS keys is an array");

    for configuration_id in ["fixture_eddsa", "fixture_es256"] {
        let configuration = &profile["credential_configurations"][configuration_id];
        let private_jwk = PrivateJwk::parse(&read_fixture(
            configuration["private_jwk_fixture"]
                .as_str()
                .expect("private_jwk_fixture is configured"),
        ))
        .expect("private issuer fixture parses");
        let public_jwk = serde_json::to_value(private_jwk.public()).expect("public JWK serialises");
        let key_id = public_jwk["kid"].as_str().expect("public JWK has kid");
        let published = public_keys
            .iter()
            .find(|key| key["kid"] == key_id)
            .expect("issuer public JWK is published");

        assert_eq!(&public_jwk, published);
        assert!(
            published.get("d").is_none(),
            "JWKS must not expose private key material"
        );
    }

    let holder_private = PrivateJwk::parse(&read_fixture(
        profile["holder_proof"]["private_jwk_fixture"]
            .as_str()
            .expect("holder private_jwk_fixture is configured"),
    ))
    .expect("holder private fixture parses");
    assert_eq!(
        did_jwk_from_public_jwk(&holder_private.public()).expect("holder did:jwk encodes"),
        meta()["holder_did"].as_str().expect("holder_did in meta")
    );
}

#[test]
fn eddsa_did_jwk_holder_proof_validates_and_es256_holder_proof_is_rejected() {
    let profile = read_fixture_json("algorithm-profile.json");
    let audience = profile["proof_audience"]
        .as_str()
        .expect("proof_audience in profile");
    let nonce = profile["proof_nonce"]
        .as_str()
        .expect("proof_nonce in profile");
    let policy = ProofValidationPolicy {
        audience,
        expected_nonce: Some(nonce),
        issuer: ProofIssuerPolicy::Optional,
        max_lifetime: Duration::from_secs(300),
        future_skew: Duration::from_secs(30),
        forbidden_holder_keys: &[],
    };

    let proof = validate_proof_jwt(&read_fixture("holder-proof-eddsa.jwt"), &policy, NOW_UNIX)
        .expect("EdDSA did:jwk holder proof must validate");
    assert_eq!(
        proof.holder_id,
        meta()["holder_did"].as_str().expect("holder_did in meta")
    );
    assert_eq!(proof.nonce.as_deref(), Some(nonce));

    assert_eq!(
        validate_proof_jwt(
            &read_fixture("holder-proof-es256-unsupported.jwt"),
            &policy,
            NOW_UNIX,
        ),
        Err(ProofError::InvalidHeader),
        "Registry Stack 1.0 must not accept ES256 holder proof"
    );
}

// ---------------------------------------------------------------------------
// Negative fixtures: each must fail with the exact error code documented in
// the conformance profile and verifier API.
// ---------------------------------------------------------------------------

#[test]
fn wrong_vct_fails_with_vct_mismatch() {
    let compact = read_fixture("wrong-vct.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("wrong-vct fixture must fail");

    assert_eq!(
        err.code(),
        "claim.vct_mismatch",
        "wrong-vct must fail with claim.vct_mismatch, got {err:?}"
    );
}

#[test]
fn expired_credential_fails_with_time_invalid() {
    let compact = read_fixture("expired.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("expired fixture must fail");

    assert_eq!(
        err.code(),
        "claim.time_invalid",
        "expired credential must fail with claim.time_invalid, got {err:?}"
    );
}

#[test]
fn unsupported_alg_fails_with_algorithm_disallowed() {
    let compact = read_fixture("unsupported-alg.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("unsupported-alg fixture must fail");

    assert_eq!(
        err.code(),
        "algorithm.disallowed",
        "unsupported alg must fail with algorithm.disallowed, got {err:?}"
    );
}

#[test]
fn wrong_kid_fails_with_key_unknown() {
    let compact = read_fixture("wrong-kid.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("wrong-kid fixture must fail");

    assert_eq!(
        err.code(),
        "key.unknown",
        "wrong kid must fail with key.unknown, got {err:?}"
    );
}

#[test]
fn missing_cnf_when_holder_binding_required_fails_with_holder_binding_required() {
    // The fixture credential was issued without holder binding. The policy
    // requires it. The verifier should fail before reaching the signature check.
    let compact = read_fixture("missing-cnf-when-binding-required.sd-jwt");
    let options = base_options().holder_binding(HolderBindingPolicy::Required);
    let err = verify_sd_jwt_vc(&compact, &jwks(), &options)
        .expect_err("missing-cnf fixture must fail when binding is required");

    assert_eq!(
        err.code(),
        "holder_binding.required",
        "missing cnf must fail with holder_binding.required, got {err:?}"
    );
}

#[test]
fn malformed_disclosure_fails_with_disclosure_digest_mismatch() {
    // The fixture has a corrupted base64url disclosure. The verifier fails at
    // the base64 decode step and maps that parse failure to
    // disclosure.digest_mismatch. The hash-comparison branch is not reached.
    let compact = read_fixture("malformed-disclosure.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("malformed-disclosure fixture must fail");

    assert_eq!(
        err.code(),
        "disclosure.digest_mismatch",
        "malformed disclosure must fail with disclosure.digest_mismatch, got {err:?}"
    );
}

#[test]
fn tampered_disclosure_fails_with_disclosure_digest_mismatch() {
    // The fixture disclosure is valid base64url-encoded JSON with three elements
    // (salt, claim name, value), so it passes the parse and structure checks.
    // The claim value has been altered, making its SHA-256 digest different from
    // every entry in the payload _sd array. The verifier reaches the
    // hash-comparison branch and returns disclosure.digest_mismatch.
    let compact = read_fixture("tampered-disclosure.sd-jwt");
    let err = verify_sd_jwt_vc(&compact, &jwks(), &base_options())
        .expect_err("tampered-disclosure fixture must fail");

    assert_eq!(
        err.code(),
        "disclosure.digest_mismatch",
        "tampered disclosure must fail with disclosure.digest_mismatch, got {err:?}"
    );
}

#[test]
fn holder_proof_mismatch_fails_with_holder_binding_proof_invalid() {
    // The credential has a valid cnf but the appended key-binding JWT was
    // signed by the wrong key (issuer key instead of holder key).
    let compact = read_fixture("holder-proof-mismatch.sd-jwt");
    let meta = meta();
    let holder_did = meta["holder_did"]
        .as_str()
        .expect("holder_did in meta")
        .to_string();
    let options = base_options().holder_binding(HolderBindingPolicy::RequiredKid(holder_did));
    let err = verify_sd_jwt_vc(&compact, &jwks(), &options)
        .expect_err("holder-proof-mismatch fixture must fail");

    assert_eq!(
        err.code(),
        "holder_binding.proof_invalid",
        "wrong holder proof must fail with holder_binding.proof_invalid, got {err:?}"
    );
}
