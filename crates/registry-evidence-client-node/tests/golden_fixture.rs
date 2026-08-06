//! Golden fixture for the JS suite's `discover`/`fetchJwks` stubs and for a
//! direct Rust-side check that a stored response still verifies.
//!
//! A JS test cannot sign an Evidence response itself: the crates that can
//! (`registry-evidence-verifier` and `registry-evidence-client`) keep their
//! test signers `#[cfg(test)]`-private, so this file builds one directly with
//! `registry-platform-crypto`, the same way those crates' own tests do.
//!
//! Regenerate with:
//! ```text
//! cargo test -p registry-evidence-client-node --test golden_fixture -- --ignored regenerate_golden_fixture
//! ```
//! The signing key is generated fresh every run and discarded; only its
//! public half is committed, inside `tests/fixtures/jwks.json`.

use std::{fs, path::Path};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ed25519_dalek::SigningKey;
use registry_evidence_client::{
    AssuranceProfile, Evidence, EvidenceObjectType, EvidenceVerificationPolicyDocument,
    ExpectedFormDocument, ExpectedOutputDocument, ExpectedScalarFormDocument,
    ExpectedSubjectDocument, JwksDocument, PublicValue, SubjectBinding, SupportedValue,
};
use registry_evidence_verifier::{
    model::FlattenedJws, verifier::verify_flattened_jws, EVIDENCE_JWS_CTY, EVIDENCE_JWS_TYP,
    EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};

/// Canonical all-zero nonce for offline fixture evaluation, matching the
/// convention `registry-evidence-verifier`'s own fixtures use. A real request
/// always carries a freshly generated nonce; this fixture never goes through
/// `prepare`, so there is nothing independent to match it against.
const FIXTURE_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const ACTIVE_KEY_ID: &str = "evidence-node-fixture-key-1";

/// The instant the committed response is signed for, shared by the generator
/// and by every check that reads the result, so nothing has to re-derive it
/// from the committed bytes.
const FIXTURE_ISSUED_AT: &str = "2026-08-01T00:00:00Z";

/// Thirty days past `FIXTURE_ISSUED_AT`, which is also the acceptance ceiling
/// the committed policy states. It has to stay inside the
/// `maximumAssertionLifetimeSeconds` bound the verification-policy contract
/// sets, or the fixture would model a policy no conformant relying party could
/// express. Nothing here needs a longer window: the checks that read the
/// committed response verify at a pinned instant rather than at the wall clock,
/// and the real-clock path is covered by signing fresh evidence instead.
const FIXTURE_LIFETIME_DAYS: i64 = 30;

fn fixtures_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

fn fixture_issued_at() -> DateTime<Utc> {
    FIXTURE_ISSUED_AT
        .parse()
        .expect("the fixture instant parses")
}

/// A fresh Ed25519 signer under the fixture's key id. The private half never
/// leaves the process that made it: regeneration commits only the public key,
/// and the real-clock check below discards the whole pair when it returns.
fn fixture_signer() -> LocalJwkSigner {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).expect("the host supplies randomness");
    let signing_key = SigningKey::from_bytes(&seed);
    let private_jwk_json = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": ACTIVE_KEY_ID,
        "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
    });
    let private_jwk =
        PrivateJwk::parse(&private_jwk_json.to_string()).expect("the generated key parses");
    LocalJwkSigner::new(private_jwk).expect("the generated key signs")
}

fn public_jwks(signer: &LocalJwkSigner) -> JwksDocument {
    JwksDocument {
        keys: vec![serde_json::to_value(signer.public_jwk()).expect("the public key serializes")],
    }
}

fn assert_fixture_shape(evidence: &Evidence) {
    assert_eq!(evidence.request_nonce, FIXTURE_NONCE);
    assert_eq!(evidence.subjects.len(), 1);
    assert_eq!(evidence.subjects[0].role, "subject");
    assert_eq!(evidence.supported_values.len(), 1);
    assert!(matches!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    ));
}

fn fixture_evidence(issued_at: DateTime<Utc>, valid_until: DateTime<Utc>) -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA_V1.to_owned(),
        assurance_profile: AssuranceProfile::Local,
        request_nonce: FIXTURE_NONCE.to_owned(),
        id: "urn:example:evidence:node-fixture".to_owned(),
        evidence_type_name: EvidenceObjectType::Evidence,
        supports_requirement: "urn:example:requirement:v1".to_owned(),
        is_conformant_to: "urn:example:evidence-type:v1".to_owned(),
        issued_by: "urn:example:issuer".to_owned(),
        provided_by: "urn:example:provider".to_owned(),
        issued_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        observed_at: issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        valid_until: valid_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        purpose: "example-purpose".to_owned(),
        audience: "urn:example:audience".to_owned(),
        configuration_revision: format!("sha256:{}", "0".repeat(64)),
        subjects: vec![SubjectBinding {
            role: "subject".to_owned(),
            binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
        }],
        supported_values: vec![SupportedValue {
            provides_value_for: "urn:example:concept:status-holds".to_owned(),
            value: PublicValue::Boolean(true),
        }],
    }
}

fn fixture_policy_document(evidence: &Evidence) -> EvidenceVerificationPolicyDocument {
    EvidenceVerificationPolicyDocument {
        expected_assurance_profile: evidence.assurance_profile,
        issued_by: evidence.issued_by.clone(),
        provided_by: evidence.provided_by.clone(),
        requirement: evidence.supports_requirement.clone(),
        evidence_type: evidence.is_conformant_to.clone(),
        purpose: evidence.purpose.clone(),
        audience: evidence.audience.clone(),
        configuration_revision: evidence.configuration_revision.clone(),
        request_nonce: evidence.request_nonce.clone(),
        expected_subjects: evidence
            .subjects
            .iter()
            .map(|subject| ExpectedSubjectDocument {
                role: subject.role.clone(),
                binding: subject.binding.clone(),
            })
            .collect(),
        expected_outputs: evidence
            .supported_values
            .iter()
            .map(|value| ExpectedOutputDocument {
                concept: value.provides_value_for.clone(),
                form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
            })
            .collect(),
        maximum_assertion_lifetime_seconds: (FIXTURE_LIFETIME_DAYS * 24 * 60 * 60) as u64,
        clock_skew_seconds: 30,
    }
}

#[derive(serde::Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
    cty: &'static str,
}

async fn sign(evidence: &Evidence, signer: &LocalJwkSigner) -> FlattenedJws {
    let payload = serde_json::to_vec(evidence).expect("evidence serializes");
    let protected = serde_json::to_vec(&ProtectedHeader {
        alg: "EdDSA",
        kid: signer.key_id(),
        typ: EVIDENCE_JWS_TYP,
        cty: EVIDENCE_JWS_CTY,
    })
    .expect("protected header serializes");

    let protected = URL_SAFE_NO_PAD.encode(protected);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{protected}.{payload}");
    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .expect("the fixture key signs");

    FlattenedJws {
        protected,
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature),
    }
}

fn write_pretty<T: serde::Serialize>(path: &Path, value: &T) {
    let mut json = serde_json::to_string_pretty(value).expect("the fixture serializes");
    json.push('\n');
    fs::write(path, json).unwrap_or_else(|error| panic!("writing {path:?} failed: {error}"));
}

/// Rewrites the three committed fixture files from a freshly generated key,
/// used once and discarded here. Not run by the ordinary suite; see the
/// module doc comment for the exact command.
#[tokio::test]
#[ignore]
async fn regenerate_golden_fixture() {
    let signer = fixture_signer();

    let issued_at = fixture_issued_at();
    let valid_until = issued_at + ChronoDuration::days(FIXTURE_LIFETIME_DAYS);
    let evidence = fixture_evidence(issued_at, valid_until);
    let policy_document = fixture_policy_document(&evidence);
    let jws = sign(&evidence, &signer).await;
    let jwks = public_jwks(&signer);

    let dir = fixtures_dir();
    fs::create_dir_all(dir).expect("the fixtures directory can be created");
    write_pretty(&dir.join("response.jws.json"), &jws);
    write_pretty(&dir.join("jwks.json"), &jwks);
    write_pretty(&dir.join("policy.json"), &policy_document);
}

/// The committed policy fixture stands for a document a relying party writes,
/// so the frozen verification-policy contract is what decides whether it is a
/// policy anyone could actually adopt. It once was not: it named an acceptance
/// window longer than the contract's own ceiling, which made the fixture a model
/// of something no conformant relying party could express.
#[test]
fn the_committed_policy_conforms_to_the_verification_policy_contract() {
    let contract: serde_norway::Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/contracts/verification-policy.schema.yaml"
    ))
    .expect("the verification policy contract is YAML");
    let contract = serde_json::to_value(contract).expect("the contract converts to JSON");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&contract)
        .expect("the verification policy contract compiles");

    let policy: serde_json::Value = serde_json::from_slice(
        &fs::read(fixtures_dir().join("policy.json")).expect("the policy fixture exists"),
    )
    .expect("the policy fixture parses");

    let violations: Vec<String> = match validator.validate(&policy) {
        Ok(()) => Vec::new(),
        Err(errors) => errors
            .map(|error| format!("{error}, at {}", error.instance_path))
            .collect(),
    };
    assert!(
        violations.is_empty(),
        "the committed policy fixture violates its contract:\n{}",
        violations.join("\n")
    );
}

/// Confirms the committed response, key set, and policy still agree, at an
/// instant inside the acceptance window the fixture states rather than at the
/// wall clock, so the JS suite can trust `jwks.json` and `response.jws.json`
/// without re-deriving them. Pinning the instant is what lets the fixture carry
/// a lifetime a relying party could adopt: it does not have to outlive the gaps
/// between regenerations.
#[test]
fn the_committed_fixture_verifies_at_its_pinned_instant() {
    let dir = fixtures_dir();
    let jws_bytes = fs::read(dir.join("response.jws.json")).expect("the response fixture exists");
    let jwks: JwksDocument =
        serde_json::from_slice(&fs::read(dir.join("jwks.json")).expect("the JWKS fixture exists"))
            .expect("the JWKS fixture parses");
    let policy_document: EvidenceVerificationPolicyDocument = serde_json::from_slice(
        &fs::read(dir.join("policy.json")).expect("the policy fixture exists"),
    )
    .expect("the policy fixture parses");

    let policy = policy_document.into_policy(fixture_issued_at() + ChronoDuration::days(1));
    let evidence = verify_flattened_jws(&jws_bytes, &jwks, &policy).expect("the fixture verifies");

    assert_fixture_shape(&evidence);
}

/// The real-clock half of the same coverage. A response signed now and verified
/// now keeps the wall-clock path through `into_policy` and
/// `verify_flattened_jws` exercised, without any committed file having to stay
/// current for years to do it.
#[tokio::test]
async fn a_freshly_signed_response_verifies_against_the_real_clock() {
    let signer = fixture_signer();
    let issued_at = Utc::now();
    let valid_until = issued_at + ChronoDuration::days(FIXTURE_LIFETIME_DAYS);
    let evidence = fixture_evidence(issued_at, valid_until);
    let policy_document = fixture_policy_document(&evidence);
    let jws_bytes = serde_json::to_vec(&sign(&evidence, &signer).await)
        .expect("the signed response serializes");

    let policy = policy_document.into_policy(Utc::now());
    let verified = verify_flattened_jws(&jws_bytes, &public_jwks(&signer), &policy)
        .expect("a freshly signed response verifies");

    assert_fixture_shape(&verified);
}
