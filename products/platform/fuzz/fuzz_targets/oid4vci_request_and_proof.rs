#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use registry_platform_oid4vci::{
    validate_proof_jwt, CredentialIssuerMetadata, CredentialOffer, CredentialRequest, NonceRequest,
    NonceResponse, ProofIssuerPolicy, ProofValidationPolicy, TokenRequest, TokenResponse,
    WireError,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 8192);
    fuzz_wire_json(&bounded);
    fuzz_proof(&bounded);
});

fn fuzz_wire_json(input: &str) {
    let _ = serde_json::from_str::<CredentialRequest>(input);
    let _ = serde_json::from_str::<CredentialOffer>(input);
    let _ = serde_json::from_str::<CredentialIssuerMetadata>(input);
    let _ = serde_json::from_str::<NonceRequest>(input);
    let _ = serde_json::from_str::<NonceResponse>(input);
    let _ = serde_json::from_str::<TokenRequest>(input);
    let _ = serde_json::from_str::<TokenResponse>(input);
    let _ = serde_json::from_str::<WireError>(input);
    let _ = serde_urlencoded::from_str::<TokenRequest>(input);
}

fn fuzz_proof(input: &str) {
    let policy = ProofValidationPolicy {
        audience: "https://issuer.example",
        expected_nonce: Some("n-1"),
        issuer: ProofIssuerPolicy::Optional,
        max_lifetime: Duration::from_secs(300),
        future_skew: Duration::from_secs(30),
        forbidden_holder_keys: &[],
    };
    let _ = validate_proof_jwt(input, &policy, 1001);
}

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
