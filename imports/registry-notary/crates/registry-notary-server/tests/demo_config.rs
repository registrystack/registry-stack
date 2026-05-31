// SPDX-License-Identifier: Apache-2.0
//! Demo configuration loading for the split Registry Notary repository.

mod common;

use registry_notary_core::{
    BulkMode, RuleConfig, SourceConnectorKind, StandaloneRegistryNotaryConfig,
};
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

#[test]
fn opencrvs_dci_demo_config_loads_validates_and_builds_router() {
    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
        );
        std::env::set_var("DCI_CLIENT_ID", "test-opencrvs-dci-client");
        std::env::set_var("DCI_CLIENT_SECRET", "test-opencrvs-dci-secret");
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/opencrvs-dci-registry-notary.yaml");
    let raw = std::fs::read_to_string(config_path).expect("OpenCRVS config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("OpenCRVS config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("opencrvs-dci-registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config.validate().expect("OpenCRVS config validates");
    let source = config
        .evidence
        .source_connections
        .get("opencrvs_crvs")
        .expect("OpenCRVS source exists");
    assert_eq!(source.bulk_mode, BulkMode::None);
    assert_eq!(source.dci.search_path, "/registry/sync/search");
    assert_eq!(source.dci.query_type, "idtype-value");
    assert_eq!(
        source.dci.registry_type.as_deref(),
        Some("ns:org:RegistryType:Civil")
    );
    assert_eq!(source.dci.registry_event_type.as_deref(), Some("birth"));

    let claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "opencrvs-birth-record-exists")
        .expect("OpenCRVS existence claim exists");
    assert_eq!(claim.value.value_type, "boolean");
    let binding = claim
        .source_bindings
        .get("birth_record")
        .expect("OpenCRVS birth record binding exists");
    assert_eq!(binding.lookup.input, "target.identifiers.UIN");
    assert_eq!(binding.lookup.field, "UIN");

    let _ = standalone_router(config).expect("OpenCRVS config builds standalone router");
}

#[test]
fn opencrvs_birth_attributes_demo_config_loads_validates_and_builds_router() {
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
        );
        std::env::set_var("DCI_CLIENT_ID", "test-opencrvs-dci-client");
        std::env::set_var("DCI_CLIENT_SECRET", "test-opencrvs-dci-secret");
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/opencrvs-dci-birth-attributes-registry-notary.yaml");
    let raw =
        std::fs::read_to_string(config_path).expect("OpenCRVS birth attributes config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("OpenCRVS birth attributes config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("opencrvs-dci-birth-attributes-registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config
        .validate()
        .expect("OpenCRVS birth attributes config validates");
    let source = config
        .evidence
        .source_connections
        .get("opencrvs_crvs_birth_attributes")
        .expect("OpenCRVS birth attributes source exists");
    assert_eq!(source.bulk_mode, BulkMode::None);
    assert_eq!(source.dci.query_type, "idtype-value");
    assert_eq!(
        source.dci.registry_type.as_deref(),
        Some("ns:org:RegistryType:Civil")
    );
    assert_eq!(source.dci.registry_event_type.as_deref(), Some("birth"));
    assert_eq!(
        source
            .dci
            .field_paths
            .get("child_given_name")
            .map(String::as_str),
        Some("/name/given_name")
    );
    assert_eq!(
        source
            .dci
            .field_paths
            .get("child_family_name")
            .map(String::as_str),
        Some("/name/surname")
    );
    assert_eq!(
        source
            .dci
            .field_paths
            .get("child_birth_date")
            .map(String::as_str),
        Some("/birth_date")
    );
    assert_eq!(
        source
            .dci
            .field_paths
            .get("child_place_of_birth")
            .map(String::as_str),
        Some("/birth_place")
    );

    let profile = config
        .evidence
        .credential_profiles
        .get("opencrvs_birth_attributes_sd_jwt")
        .expect("OpenCRVS birth attributes SD-JWT VC profile exists");
    assert_eq!(profile.holder_binding.mode, "none");
    assert_eq!(profile.allowed_claims.len(), 4);

    for (claim_id, expected_field, expected_type) in [
        ("opencrvs-child-given-name", "child_given_name", "string"),
        ("opencrvs-child-family-name", "child_family_name", "string"),
        ("opencrvs-child-date-of-birth", "child_birth_date", "date"),
        (
            "opencrvs-child-place-of-birth",
            "child_place_of_birth",
            "string",
        ),
    ] {
        let claim = config
            .evidence
            .claims
            .iter()
            .find(|claim| claim.id == claim_id)
            .expect("attribute claim exists");
        assert_eq!(claim.value.value_type, expected_type);
        assert_eq!(
            claim.credential_profiles,
            vec!["opencrvs_birth_attributes_sd_jwt".to_string()]
        );
        assert!(matches!(
            &claim.rule,
            RuleConfig::Extract { source, field }
                if source == "birth_record" && field == expected_field
        ));
        let binding = claim
            .source_bindings
            .get("birth_record")
            .expect("birth record binding exists");
        assert_eq!(binding.lookup.input, "target.identifiers.UIN");
        assert_eq!(binding.lookup.field, "UIN");
        assert!(binding.fields.contains_key(expected_field));
    }

    let _ = standalone_router(config)
        .expect("OpenCRVS birth attributes config builds standalone router");
}

#[test]
fn opencrvs_demographic_dci_demo_config_loads_validates_and_builds_router() {
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
        );
        std::env::set_var("DCI_CLIENT_ID", "test-opencrvs-dci-client");
        std::env::set_var("DCI_CLIENT_SECRET", "test-opencrvs-dci-secret");
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/opencrvs-dci-demographic-registry-notary.yaml");
    let raw =
        std::fs::read_to_string(config_path).expect("OpenCRVS demographic config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("OpenCRVS demographic config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("opencrvs-dci-demographic-registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config
        .validate()
        .expect("OpenCRVS demographic config validates");
    let source = config
        .evidence
        .source_connections
        .get("opencrvs_crvs_demographic")
        .expect("OpenCRVS demographic source exists");
    assert_eq!(source.bulk_mode, BulkMode::None);
    assert_eq!(source.dci.query_type, "expression");
    assert_eq!(
        source.dci.registry_type.as_deref(),
        Some("ns:org:RegistryType:Civil")
    );
    assert_eq!(source.dci.registry_event_type.as_deref(), Some("birth"));

    let claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "opencrvs-birth-record-exists-by-demographics")
        .expect("OpenCRVS demographic existence claim exists");
    assert_eq!(claim.value.value_type, "boolean");
    assert_eq!(
        claim.credential_profiles,
        vec!["opencrvs_demographic_sd_jwt".to_string()]
    );
    let binding = claim
        .source_bindings
        .get("birth_record")
        .expect("OpenCRVS demographic birth record binding exists");
    assert_eq!(binding.lookup.input, "target.attributes.given_name");
    assert_eq!(binding.lookup.field, "given_name");
    assert_eq!(binding.query_fields.len(), 3);
    assert_eq!(
        binding.query_fields[0].input,
        "target.attributes.given_name"
    );
    assert_eq!(binding.query_fields[0].field, "given_name");
    assert_eq!(
        binding.query_fields[1].input,
        "target.attributes.family_name"
    );
    assert_eq!(binding.query_fields[1].field, "surname");
    assert_eq!(binding.query_fields[2].input, "target.attributes.birthdate");
    assert_eq!(binding.query_fields[2].field, "birth_date");
    assert_eq!(
        binding.matching.sufficient_target_inputs,
        vec![vec![
            "target.attributes.given_name".to_string(),
            "target.attributes.family_name".to_string(),
            "target.attributes.birthdate".to_string()
        ]]
    );
    assert_eq!(
        binding.matching.allowed_target_inputs,
        vec![
            "target.attributes.given_name".to_string(),
            "target.attributes.family_name".to_string(),
            "target.attributes.birthdate".to_string()
        ]
    );

    let profile = config
        .evidence
        .credential_profiles
        .get("opencrvs_demographic_sd_jwt")
        .expect("OpenCRVS demographic SD-JWT VC profile exists");
    assert_eq!(profile.holder_binding.mode, "none");

    let _ =
        standalone_router(config).expect("OpenCRVS demographic config builds standalone router");
}

#[test]
fn opencrvs_rda_demographic_demo_config_loads_validates_and_builds_router() {
    let _guard = common::issuer_jwk_guard();

    unsafe {
        std::env::set_var(
            "REGISTRY_NOTARY_API_KEY_HASH",
            "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
        );
        std::env::set_var(
            "EVIDENCE_SOURCE_REGISTRY_RELAY_TOKEN",
            "test-registry-relay-token",
        );
        std::env::set_var("REGISTRY_NOTARY_ISSUER_JWK", DEMO_ISSUER_JWK);
        std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config_path = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("demo/config/opencrvs-rda-demographic-registry-notary.yaml");
    let raw =
        std::fs::read_to_string(config_path).expect("OpenCRVS RDA demographic config is readable");
    let mut config: StandaloneRegistryNotaryConfig =
        serde_norway::from_str(&raw).expect("OpenCRVS RDA demographic config deserializes");
    let temp = tempfile::TempDir::new().expect("tempdir");
    config.audit.path = Some(
        temp.path()
            .join("opencrvs-rda-demographic-registry-notary-audit.jsonl")
            .to_string_lossy()
            .into_owned(),
    );

    config
        .validate()
        .expect("OpenCRVS RDA demographic config validates");
    let source = config
        .evidence
        .source_connections
        .get("registry_relay_crvs")
        .expect("Registry Relay CRVS source exists");
    assert_eq!(source.bulk_mode, BulkMode::None);
    assert!(source.allow_insecure_localhost);

    let claim = config
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "opencrvs-rda-birth-record-exists-by-demographics")
        .expect("OpenCRVS RDA demographic existence claim exists");
    assert_eq!(
        claim.credential_profiles,
        vec!["opencrvs_rda_demographic_sd_jwt".to_string()]
    );
    let binding = claim
        .source_bindings
        .get("birth_record")
        .expect("OpenCRVS RDA demographic birth record binding exists");
    assert_eq!(binding.connector, SourceConnectorKind::RegistryDataApi);
    assert_eq!(binding.lookup.input, "target.attributes.given_name");
    assert_eq!(binding.lookup.field, "given_name");
    assert_eq!(binding.query_fields.len(), 3);
    assert_eq!(binding.query_fields[0].field, "given_name");
    assert_eq!(binding.query_fields[1].field, "surname");
    assert_eq!(binding.query_fields[2].field, "birth_date");

    let _ = standalone_router(config)
        .expect("OpenCRVS RDA demographic config builds standalone router");
}
