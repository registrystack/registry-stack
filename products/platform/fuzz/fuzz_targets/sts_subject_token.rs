#![no_main]

use std::sync::{Arc, OnceLock};

use jsonwebtoken::Algorithm;
use libfuzzer_sys::fuzz_target;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use registry_platform_sts::{
    NotaryAuthorizationDetails, OidcSubjectTokenVerifier, SubjectTokenVerifier,
    TokenExchangeRequest,
};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let bounded = take_chars(input, 8192);

    // Wire message parsing: the untrusted token-exchange request shapes.
    let _ = serde_json::from_str::<TokenExchangeRequest>(&bounded);
    let _ = serde_json::from_str::<NotaryAuthorizationDetails>(&bounded);

    if bounded.trim().is_empty() {
        return;
    }

    // The real JWT/JOSE parse boundary: decode_header, algorithm/typ
    // enforcement, and kid lookup all run on every fuzzed token.
    let _ = runtime().block_on(verifier().verify_subject_token(&bounded));
});

fn verifier() -> &'static OidcSubjectTokenVerifier {
    static VERIFIER: OnceLock<OidcSubjectTokenVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        // The JWKS URI is loopback-only and unreachable by construction: the
        // default `FetchUrlPolicy::strict()` rejects loopback hosts during URL
        // validation, before any socket is opened, so key resolution always
        // fails fast and fully offline. This still exercises the real JOSE
        // header decode, algorithm and `typ` enforcement, and kid-lookup paths
        // on every fuzzed token, through the actual product verifier rather
        // than a locally re-declared mirror.
        let fetcher = JwksFetcher::new(
            "https://127.0.0.1/jwks".to_string(),
            JwksFetcherConfig::defaults(),
        );
        let config = TokenVerifierConfig::access_token_profile(
            "https://issuer.example",
            vec!["https://notary.example".to_string()],
            vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
            vec!["at+jwt".to_string()],
        );
        let token_verifier = TokenVerifier::new(config, Arc::new(fetcher));
        OidcSubjectTokenVerifier::new(Arc::new(token_verifier), "sub")
    })
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("fuzz runtime builds")
    })
}

fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
