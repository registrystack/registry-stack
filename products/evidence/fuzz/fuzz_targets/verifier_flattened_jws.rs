#![no_main]

//! Flattened-JWS response verification: the strict parse of an untrusted
//! serialized response, the protected-header contract, the ES256 signature
//! against the pinned key set, the payload contract, and the policy
//! comparison (`registry-evidence-verifier`).

mod verifier_common;

use libfuzzer_sys::fuzz_target;
use registry_evidence_verifier::verifier::verify_flattened_jws_report;
use verifier_common::{fixture, parse_bounded_evidence, runtime};

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let serialized = match parse_bounded_evidence(data) {
        // Structurally valid inputs are signed with the held test key so
        // verification reaches the payload contract and policy stages.
        Some(evidence) => match runtime().block_on(fixture.signer.sign_json(&evidence)) {
            Ok(jws) => serde_json::to_vec(&jws).expect("signed JWS serializes"),
            Err(_) => data.to_vec(),
        },
        // Everything else exercises the untrusted parsing stages directly.
        None => data.to_vec(),
    };
    let _ = verify_flattened_jws_report(&serialized, &fixture.jwks, &fixture.policy);
});
