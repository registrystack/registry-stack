#![no_main]

use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use registry_platform_crypto::PublicJwk;
use registry_platform_sdjwt::{
    validate_holder_proof, validate_holder_proof_for_confirmation, HolderConfirmation,
    HolderProofBindings, HolderProofPolicy,
};
use sha2::{Digest, Sha256};

const HOLDER_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:jwk:holder#key-1"}"#;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 8192);
    let holder_jwk = holder_jwk();
    let claim_set = vec!["claim-a".to_string()];
    let disclosure_hash = Sha256::digest(b"redacted-disclosure-hash");
    let bindings = HolderProofBindings {
        expected_sub: "did:example:subject",
        evaluation_id: "eval-1",
        credential_profile: "profile-a",
        disclosure_hash: disclosure_hash.as_slice(),
        claim_set: &claim_set,
    };
    let policy = HolderProofPolicy {
        audience: "https://issuer.example".to_string(),
        max_lifetime: Duration::from_secs(300),
    };
    let confirmation = HolderConfirmation {
        jwk: holder_jwk.clone(),
        kid: Some("did:jwk:holder#key-1".to_string()),
    };

    let _ = validate_holder_proof(&bounded, holder_jwk, &bindings, &policy, 1001);
    let _ =
        validate_holder_proof_for_confirmation(&bounded, &confirmation, &bindings, &policy, 1001);
});

fn holder_jwk() -> &'static PublicJwk {
    static HOLDER: OnceLock<PublicJwk> = OnceLock::new();
    HOLDER.get_or_init(|| PublicJwk::parse(HOLDER_PUBLIC_JWK).expect("holder public JWK parses"))
}

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
