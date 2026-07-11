    // SPDX-License-Identifier: Apache-2.0

    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use axum::body::Body;
    use axum::extract::Query;
    use axum::response::Redirect;
    use axum::routing::{get, post};
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
        EvaluateRequest, SelfAttestationDenialCode, SelfAttestationRateLimitsConfig,
        SourceConnectionConfig, SourceLookupConfig, SourceQueryFieldConfig,
        FORMAT_CLAIM_RESULT_JSON,
    };
    #[cfg(feature = "pkcs11")]
    use registry_notary_core::{ClaimProvenance, ClaimResultView, TargetRefView};
    use registry_notary_source_adapter_sidecar::{sidecar_router, SidecarConfig};

    const SOURCE_ADAPTER_SIDECAR_TOKEN_ENV: &str = "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN";
    const SOURCE_ADAPTER_SIDECAR_TOKEN_HASH_ENV: &str = "TEST_SOURCE_ADAPTER_SIDECAR_TOKEN_HASH";
    const SOURCE_ADAPTER_SIDECAR_TOKEN: &str = "source-adapter-sidecar-token";
    const SOURCE_ADAPTER_SIDECAR_TOKEN_HASH: &str =
        "sha256:95daed38ef01a80fd7273dd22da0bd6553958630af3f87eae1bc02056ad9f828";
    const SOURCE_ADAPTER_SPIKE_PURPOSE: &str = "https://purpose.example.test/eligibility";
    const SOURCE_ADAPTER_PRODUCT: &str = "registry-notary-source-adapter-sidecar";
    const SOURCE_ADAPTER_INSTANCE_ID: &str = "demo";
    const SOURCE_ADAPTER_ENVIRONMENT: &str = "staging";
    const SOURCE_ADAPTER_STREAM_ID: &str = "source-adapter-sidecar-runtime";
    const HTTP_JSON_CREDENTIAL_ENV: &str = "TEST_HTTP_JSON_READER_CREDENTIAL_JSON";
    const TEST_AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_NOTARY_TEST_AUDIT_HASH_SECRET";
    static HTTP_JSON_SIDECAR_ENV_LOCK: Mutex<()> = Mutex::const_new(());
    const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
    const TEST_ISSUER_JWK_WITH_KID: &str = r##"{"kty":"OKP","crv":"Ed25519","kid":"did:web:issuer.example#file-watch","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"##;
    const TEST_ROTATED_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"8jFBgUJxaaQimd4NjzxhvPYyNbcOnnZsqOntZbpP3Xk","x":"XvW-aWwJCWSYoYudTB9OZqNHURKElnnyGNa6DQNjzZk","alg":"EdDSA"}"#;
    const TEST_OLD_ISSUER_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#old"}"##;
    const TEST_OLD_HSM_PUBLIC_JWK: &str = r##"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.example#hsm-old"}"##;
    #[cfg(feature = "pkcs11")]
    static SOFTHSM_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
