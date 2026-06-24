#![no_main]

use libfuzzer_sys::fuzz_target;
use registry_platform_authcommon::{
    fingerprint_api_key, parse_bearer_token, parse_fingerprint, validate_api_key_entropy,
    verify_api_key, CredentialFingerprintRef,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 4096);
    let _ = parse_bearer_token(&bounded);
    let _ = parse_fingerprint(&bounded);
    let _ = validate_api_key_entropy(&bounded);
    let _ = serde_json::from_str::<CredentialFingerprintRef>(&bounded);

    if bounded.len() <= 256 {
        let fingerprint = fingerprint_api_key(&bounded);
        let _ = parse_fingerprint(&fingerprint);
        let _ = verify_api_key(&bounded, &fingerprint);
        let _ = verify_api_key(&bounded, &bounded);
    }
});

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
