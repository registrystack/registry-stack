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
//!   cargo test -p registry-notary-server sd_jwt_vc_verifier_compat
//!
//! The harness requires no secret material and no network access.
//! Fixtures are pre-generated synthetic material. Regenerate them with:
//!   cargo run -p xtask -- gen-sd-jwt-vc-fixtures

use std::path::Path;

use registry_notary_client::verifier::verify_sd_jwt_vc;
use registry_notary_client::{HolderBindingPolicy, VerifyOptions};
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
        .join("tests/fixtures/sd_jwt_vc")
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
