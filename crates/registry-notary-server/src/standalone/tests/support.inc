    // SPDX-License-Identifier: Apache-2.0

    use super::*;

    use axum::body::Body;
    use axum::routing::get;
    use axum_test::TestServer;
    #[cfg(feature = "pkcs11")]
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    #[cfg(feature = "pkcs11")]
    use base64::Engine;
    use registry_notary_core::{
        tokens::{
            mint_access_token, AccessTokenClaims, BoundSubject,
            NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION, NOTARY_AUTHORIZATION_DETAILS_TYPE,
            NOTARY_TRANSACTION_TOKEN_JWT_TYP,
        },
        SelfAttestationDenialCode, SelfAttestationRateLimitsConfig,
    };
    #[cfg(feature = "pkcs11")]
    use registry_notary_core::{ClaimProvenance, ClaimResultView, TargetRefView};
    const TEST_AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_NOTARY_TEST_AUDIT_HASH_SECRET";
    const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
    const TEST_ISSUER_JWK_WITH_KID: &str = r##"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#file-watch","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"##;
    const TEST_ROTATED_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
    const TEST_OLD_ISSUER_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#old"}"##;
    const TEST_OLD_HSM_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm-old"}"##;
    #[cfg(feature = "pkcs11")]
    static SOFTHSM_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
