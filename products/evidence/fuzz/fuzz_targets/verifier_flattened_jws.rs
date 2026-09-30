#![no_main]

//! Flattened-JWS response verification: the strict parse of an untrusted
//! serialized response, the protected-header contract, the ES256 signature
//! against the pinned key set, the strict payload parse and payload contract,
//! and the policy comparison (`registry-evidence-verifier`).

mod verifier_common;

use libfuzzer_sys::fuzz_target;
use registry_evidence_verifier::verifier::verify_flattened_jws_report;
use verifier_common::{fixture, parse_bounded_evidence, runtime};

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();

    // The raw input as an untrusted serialized response exercises the outer
    // parse and the protected-header and signature stages directly.
    let _ = verify_flattened_jws_report(data, &fixture.jwks, &fixture.policy);

    // The raw input as the payload of an authentically signed response reaches
    // the strict payload parse and payload contract with bytes serde never
    // normalized: duplicate members, odd numbers, and malformed text included.
    let jws = runtime()
        .block_on(fixture.signer.sign_payload(data))
        .expect("the fixture signer signs any payload");
    let serialized = serde_json::to_vec(&jws).expect("signed JWS serializes");
    let _ = verify_flattened_jws_report(&serialized, &fixture.jwks, &fixture.policy);

    // Structurally valid Evidence is re-serialized and signed so verification
    // reaches the policy comparison.
    if let Some(evidence) = parse_bounded_evidence(data) {
        let jws = runtime()
            .block_on(fixture.signer.sign_json(&evidence))
            .expect("the fixture signer signs parsed Evidence");
        let serialized = serde_json::to_vec(&jws).expect("signed JWS serializes");
        let _ = verify_flattened_jws_report(&serialized, &fixture.jwks, &fixture.policy);
    }
});
