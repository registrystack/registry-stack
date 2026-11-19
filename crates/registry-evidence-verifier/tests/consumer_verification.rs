//! Runs the published consumer verification vector through the public API.
//!
//! The vector under `products/evidence/fixtures/conformance/consumer-verification/`
//! is what a relying party's own test suite runs against its verifier: one
//! signed response, the public key set, the retained request, the expectations,
//! and the instants and changes that must be accepted or refused. This test
//! keeps the vector honest against the reference verifier.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use registry_evidence_verifier::{
    model::JwksDocument,
    verifier::{verify_flattened_jws, EvidenceVerificationPolicyDocument},
};
use serde_json::Value;

fn vector_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/conformance/consumer-verification")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{} reads: {error}", path.display()))
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&read(path)).expect("vector file is JSON")
}

#[test]
fn the_published_consumer_vector_is_accepted_and_refused_as_stated() {
    let directory = vector_directory();
    let cases = json(&directory.join("cases.json"));
    assert_eq!(
        cases["fixture"],
        "registry.evidence.consumer-verification/v1"
    );
    assert_eq!(cases["syntheticOnly"], true);
    let member = |name: &str| directory.join(cases[name].as_str().expect("path is text"));

    let request = json(&member("request"));
    let response = read(&member("response"));
    let jwks: JwksDocument =
        serde_json::from_slice(&read(&member("trustedJwks"))).expect("JWKS reads");
    let policy = json(&member("policy"));

    // The expectations come from the retained request, never from the response.
    assert_eq!(policy["requestNonce"], request["requestNonce"]);
    assert_eq!(policy["purpose"], request["purpose"]);
    assert_eq!(policy["requirement"], request["requirement"]);

    // The signed payload is the exact golden assertion, so the vector cannot
    // drift from the conformance fixtures it is built on.
    let jws: Value = serde_json::from_slice(&response).expect("response is JSON");
    let payload = URL_SAFE_NO_PAD
        .decode(jws["payload"].as_str().expect("payload is text"))
        .expect("payload is unpadded base64url");
    assert_eq!(
        payload,
        read(&directory.join("../golden/adult-evidence.json"))
    );

    let mut accepted = 0;
    let mut refused = 0;
    for case in cases["cases"].as_array().expect("cases are a list") {
        let id = case["id"].as_str().expect("case has an id");
        let mut expectations = policy.clone();
        if let Some(changes) = case.get("policyChanges") {
            for (key, value) in changes.as_object().expect("changes are an object") {
                assert!(
                    expectations.get(key).is_some(),
                    "{id} changes a known member"
                );
                expectations[key] = value.clone();
            }
        }
        let mut serialized = response.clone();
        match case.get("responseChange").and_then(Value::as_str) {
            None => {}
            Some("replace-first-payload-character") => {
                let mut changed = jws.clone();
                let payload = changed["payload"].as_str().expect("payload is text");
                let first = if payload.starts_with('A') { "B" } else { "A" };
                changed["payload"] = Value::String(format!("{first}{}", &payload[1..]));
                serialized = serde_json::to_vec(&changed).expect("serializes");
            }
            Some(other) => panic!("{id} names an unknown response change {other}"),
        }
        let verify_at: DateTime<Utc> = case["verifyAt"]
            .as_str()
            .expect("verifyAt is text")
            .parse()
            .expect("verifyAt is RFC 3339");
        let document: EvidenceVerificationPolicyDocument =
            serde_json::from_value(expectations).expect("policy document reads");
        let policy_at = document
            .try_into_policy(verify_at)
            .expect("policy is inside the contract bounds");
        let outcome = verify_flattened_jws(&serialized, &jwks, &policy_at);

        match case["result"].as_str() {
            Some("accept") => {
                let evidence = outcome.unwrap_or_else(|error| {
                    panic!("{id} must be accepted, refused as {}", error.kind())
                });
                assert_eq!(evidence.supported_values.len(), 1, "{id}");
                accepted += 1;
            }
            Some("refuse") => {
                let error = match outcome {
                    Ok(_) => panic!("{id} must be refused"),
                    Err(error) => error,
                };
                assert_eq!(Some(error.kind()), case["verifierKind"].as_str(), "{id}");
                refused += 1;
            }
            other => panic!("{id} has an unknown result {other:?}"),
        }
    }
    assert!(accepted >= 1 && refused >= 1);
}
