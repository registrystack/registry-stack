// SPDX-License-Identifier: Apache-2.0
//! Microbenchmarks for the claim-verification hot path.
//!
//! Covers:
//! - `normalize_claim_value_for_hash` on a single field (small) and a
//!   mixed-type object (typical).
//! - `ClaimVerificationHasher::hmac_hex` end-to-end (canonicalize +
//!   HMAC-SHA256) at small (1 field) and typical (8 fields, mixed types)
//!   claim sizes.
//! - `jwt_receipt::encode` (Ed25519 compact JWS) for a full receipt
//!   payload -- the JWT signing cost dominates this group.
//!
//! Skipped:
//! - `canonical_json` is `pub(crate)` and therefore not reachable from
//!   bench code. Its cost is captured indirectly by the `hmac_hex`
//!   benches, which call it on every iteration.

use std::hint::black_box;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::claim_verification::{
    normalize_claim_value_for_hash, normalize_claims_for_hash, ClaimVerificationHasher,
};
use registry_relay::provenance::jwt_receipt::{self, ClaimVerificationReceiptInputs};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{SigningAlgorithm, Signer};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const BENCH_KEY_HEX: &str =
    "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const BENCH_KEY_ID: &str = "bench-binding-key";

fn make_hasher() -> ClaimVerificationHasher {
    ClaimVerificationHasher::from_encoded_key(BENCH_KEY_ID.to_string(), BENCH_KEY_HEX)
        .expect("bench key decodes")
}

/// One-field claim set: smallest realistic input.
fn small_claims() -> BTreeMap<String, Value> {
    BTreeMap::from([("family_name".to_string(), json!("durand"))])
}

/// Eight-field claim set with mixed types: string, integer, float,
/// boolean, null -- representative of a typical civil-registry check.
fn typical_claims() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("family_name".to_string(), json!("durand")),
        ("given_name".to_string(), json!("Marie Claire")),
        ("date_of_birth".to_string(), json!("1992-04-18")),
        ("birth_order".to_string(), json!(1)),
        ("weight_kg".to_string(), json!(3.42)),
        ("is_twin".to_string(), json!(false)),
        ("middle_name".to_string(), Value::Null),
        ("nationality".to_string(), json!("FRA")),
    ])
}

/// Full envelope passed to `hmac_hex` -- matches the production shape
/// used in the claim-verification handler.
fn hmac_envelope(claims: &BTreeMap<String, Value>) -> Value {
    json!({
        "version": 1,
        "verification_id": "01J5K8M0000000000000000ABC",
        "dataset_id": "civil_registry",
        "entity": "birth_record",
        "ruleset": "identity-match-v1",
        "purpose": "benefits-eligibility",
        "claims": normalize_claims_for_hash(claims),
        "evidence": []
    })
}

/// Build a fresh EdDSA software signer from a randomly generated key.
/// Called once per benchmark function (outside the hot loop).
fn make_signer() -> SoftwareSigner {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(d_bytes),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    });
    SoftwareSigner::from_jwk_str(
        &serde_json::to_string(&jwk).unwrap(),
        SigningAlgorithm::EdDSA,
        "did:web:bench.example#key-1".to_string(),
    )
    .expect("bench signer builds")
}

fn receipt_inputs(claim_hash: &str) -> ClaimVerificationReceiptInputs {
    let issued_at = OffsetDateTime::from_unix_timestamp(1_779_013_800).unwrap();
    let valid_until = issued_at + time::Duration::seconds(300);
    ClaimVerificationReceiptInputs {
        issuer: "did:web:data.example.gov".to_string(),
        subject: "client:benefits-service".to_string(),
        audience: "client:benefits-service".to_string(),
        issued_at,
        valid_until,
        verification_id: "01J5K8M0000000000000000ABC".to_string(),
        dataset: "civil_registry".to_string(),
        entity: "birth_record".to_string(),
        decision: "match".to_string(),
        ruleset: "identity-match-v1".to_string(),
        purpose_declared: Some("benefits-eligibility".to_string()),
        checked_at: "2026-05-17T10:30:00Z".to_string(),
        claim_hash: claim_hash.to_string(),
        evidence_hash: None,
    }
}

// ---------------------------------------------------------------------------
// normalize_claim_value_for_hash
// ---------------------------------------------------------------------------

fn benchmark_normalize_small(c: &mut Criterion) {
    // Bench the normalization of a single string field.
    let value = json!("Marie Claire  Durand");
    c.bench_function("claim_verification/normalize_small", |b| {
        b.iter(|| normalize_claim_value_for_hash(black_box(&value)));
    });
}

fn benchmark_normalize_typical(c: &mut Criterion) {
    // Bench normalization of a mixed-type object (8 fields).
    let claims = typical_claims();
    let value = Value::Object(
        claims
            .into_iter()
            .map(|(k, v)| (k, v))
            .collect::<serde_json::Map<_, _>>(),
    );
    c.bench_function("claim_verification/normalize_typical", |b| {
        b.iter(|| normalize_claim_value_for_hash(black_box(&value)));
    });
}

// ---------------------------------------------------------------------------
// hmac_hex (canonicalize + HMAC-SHA256)
// ---------------------------------------------------------------------------

fn benchmark_hmac_small(c: &mut Criterion) {
    let hasher = make_hasher();
    let claims = small_claims();
    let envelope = hmac_envelope(&claims);
    c.bench_function("claim_verification/hmac_small", |b| {
        b.iter(|| hasher.hmac_hex(black_box(&envelope)).expect("hmac"));
    });
}

fn benchmark_hmac_typical(c: &mut Criterion) {
    let hasher = make_hasher();
    let claims = typical_claims();
    let envelope = hmac_envelope(&claims);
    c.bench_function("claim_verification/hmac_typical", |b| {
        b.iter(|| hasher.hmac_hex(black_box(&envelope)).expect("hmac"));
    });
}

// ---------------------------------------------------------------------------
// jwt_receipt::encode (Ed25519 compact JWS)
// ---------------------------------------------------------------------------

fn benchmark_jwt_receipt_small(c: &mut Criterion) {
    // claim_hash matches what the small-claim HMAC bench produces.
    let signer = make_signer();
    let hasher = make_hasher();
    let claims = small_claims();
    let envelope = hmac_envelope(&claims);
    let claim_hash = hasher.hmac_hex(&envelope).expect("hmac");
    let inputs = receipt_inputs(&claim_hash);

    c.bench_function("claim_verification/jwt_receipt_small", |b| {
        b.iter(|| {
            jwt_receipt::encode(black_box(&signer as &dyn Signer), black_box(inputs.clone()))
                .expect("receipt encodes")
        });
    });
}

fn benchmark_jwt_receipt_typical(c: &mut Criterion) {
    let signer = make_signer();
    let hasher = make_hasher();
    let claims = typical_claims();
    let envelope = hmac_envelope(&claims);
    let claim_hash = hasher.hmac_hex(&envelope).expect("hmac");
    let inputs = receipt_inputs(&claim_hash);

    c.bench_function("claim_verification/jwt_receipt_typical", |b| {
        b.iter(|| {
            jwt_receipt::encode(black_box(&signer as &dyn Signer), black_box(inputs.clone()))
                .expect("receipt encodes")
        });
    });
}

// ---------------------------------------------------------------------------
// Criterion wiring
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets =
        benchmark_normalize_small,
        benchmark_normalize_typical,
        benchmark_hmac_small,
        benchmark_hmac_typical,
        benchmark_jwt_receipt_small,
        benchmark_jwt_receipt_typical
}
criterion_main!(benches);
