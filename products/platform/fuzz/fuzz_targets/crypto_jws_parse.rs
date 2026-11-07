#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use registry_platform_crypto::jws::{parse_compact_jws, JwsLimits};
use registry_platform_crypto::{PublicJwk, SigningAlgorithm};

const KEY: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"fuzz"}"#;

fn key() -> &'static PublicJwk {
    static KEY_CELL: OnceLock<PublicJwk> = OnceLock::new();
    KEY_CELL.get_or_init(|| PublicJwk::parse(KEY).expect("fixed fuzz key"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    let limits = JwsLimits::default();
    let Ok(parsed) = parse_compact_jws(token, &limits) else {
        return;
    };
    let _ = parsed.header();
    let _ = parsed.algorithm();
    let _ = parsed.verify(
        key(),
        &[SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
    );
});
