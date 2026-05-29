// SPDX-License-Identifier: Apache-2.0
//! Demo configuration loading for the split Registry Notary repository.

mod common;

use registry_notary_core::{BulkMode, StandaloneRegistryNotaryConfig};
use registry_notary_server::standalone_router;

const DEMO_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn split_demo_config_loads_validates_and_builds_router() {
    // Hold the shared lock for the duration of this test to prevent a race
    // with decentralized_cross_source_cel, which sets the same env var.
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:b41153a98b372cb2ec4735b53df68a344dabe5a6664f7f49264fb30f385959ea",
        );
        std::env::set_var(
            "REGISTRY_NOTARY_BEARER_TOKEN_HASH",
            "sha256:41830efe927abce7d916b63a977eafc48bc2795829060752fa902d1f186fe300",
        );
        std::env::set_var(
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN",
            "demo-evidence-casework-system",
        );
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/registry-notary.yaml");
    let raw = std::fs::read_to_string(config_path).expect("demo config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("demo config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config.validate().expect("demo config validates");
    let _ = standalone_router(config).expect("demo config builds standalone router");
}

#[test]
fn openspp_disability_demo_config_loads_validates_and_builds_router() {
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:b41153a98b372cb2ec4735b53df68a344dabe5a6664f7f49264fb30f385959ea",
        );
        std::env::set_var("OPENSPP_DCI_TOKEN", "test-openspp-dci-token");
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/openspp-disability-registry-notary.yaml");
    let raw = std::fs::read_to_string(config_path).expect("OpenSPP config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("OpenSPP config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("openspp-disability-registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config.validate().expect("OpenSPP config validates");
    let source = config
        .evidence
        .source_connections
        .get("openspp_disability")
        .expect("OpenSPP disability source exists");
    assert_eq!(source.bulk_mode, BulkMode::None);
    assert_eq!(
        source.dci.search_path,
        "/dci_api/v1/disability/registry/sync/search"
    );
    assert_eq!(source.dci.receiver_id.as_deref(), Some("openspp"));
    assert_eq!(source.dci.signature.as_deref(), Some(""));

    let profile = config
        .evidence
        .credential_profiles
        .get("openspp_disability_sd_jwt")
        .expect("OpenSPP SD-JWT VC profile exists");
    assert_eq!(profile.holder_binding.mode, "none");
    assert!(profile.holder_binding.proof_of_possession.is_none());

    let review_category = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "disability-review-category")
        .expect("review category claim exists");
    assert_eq!(review_category.value.value_type, "string");

    let _ = standalone_router(config).expect("OpenSPP config builds standalone router");
}
