// SPDX-License-Identifier: Apache-2.0
//! Demo configuration loading for the split Registry Witness repository.

mod common;

use registry_witness_core::StandaloneRegistryWitnessConfig;
use registry_witness_server::standalone_router;

const DEMO_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn split_demo_config_loads_validates_and_builds_router() {
    // Hold the shared lock for the duration of this test to prevent a race
    // with decentralized_cross_source_cel, which sets the same env var.
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_WITNESS_API_KEY_HASH",
            "sha256:b41153a98b372cb2ec4735b53df68a344dabe5a6664f7f49264fb30f385959ea",
        );
        std::env::set_var(
            "REGISTRY_WITNESS_BEARER_TOKEN_HASH",
            "sha256:41830efe927abce7d916b63a977eafc48bc2795829060752fa902d1f186fe300",
        );
        std::env::set_var(
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN",
            "demo-evidence-casework-system",
        );
        std::env::set_var("REGISTRY_WITNESS_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_WITNESS_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/registry-witness.yaml");
    let raw = std::fs::read_to_string(config_path).expect("demo config is readable");
    let mut config: StandaloneRegistryWitnessConfig =
        serde_norway::from_str(&raw).expect("demo config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("registry-witness-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config.validate().expect("demo config validates");
    let _ = standalone_router(config).expect("demo config builds standalone router");
}
