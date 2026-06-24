// SPDX-License-Identifier: Apache-2.0
//! Focused config-loading coverage for the decentralized demo Relay pack.

use std::env;
use std::path::{Path, PathBuf};

use registry_relay::config::{self, AuditSinkConfig};
use sha2::{Digest, Sha256};

fn make_fingerprint(plaintext: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plaintext)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn relay_config(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("demo/decentralized/config/relay")
        .join(name)
}

fn decentralized_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("demo/decentralized")
        .join(path)
}

const HASH_ENVS: &[&str] = &[
    "CIVIL_METADATA_CLIENT_HASH",
    "CIVIL_EVIDENCE_SOURCE_HASH",
    "CIVIL_EVIDENCE_ONLY_HASH",
    "CIVIL_ROW_READER_HASH",
    "SHARED_CIVIL_EVIDENCE_SOURCE_HASH",
    "SOCIAL_METADATA_CLIENT_HASH",
    "SOCIAL_EVIDENCE_SOURCE_HASH",
    "SOCIAL_EVIDENCE_ONLY_HASH",
    "SOCIAL_ROW_READER_HASH",
    "SOCIAL_AGGREGATE_READER_HASH",
    "SHARED_SOCIAL_EVIDENCE_SOURCE_HASH",
    "HEALTH_METADATA_CLIENT_HASH",
    "HEALTH_EVIDENCE_SOURCE_HASH",
    "HEALTH_EVIDENCE_ONLY_HASH",
    "HEALTH_ROW_READER_HASH",
    "SHARED_HEALTH_EVIDENCE_SOURCE_HASH",
];

fn seed_demo_secret_env() {
    for name in HASH_ENVS {
        env::set_var(name, make_fingerprint(name.as_bytes()));
    }
}

#[test]
fn decentralized_demo_configs_load() {
    seed_demo_secret_env();

    #[cfg(feature = "spdci-api-standards")]
    let configs = [
        (
            "civil-registry-relay.yaml",
            "civil_registry",
            "civil_person",
            "csv",
        ),
        (
            "social-protection-registry-relay.yaml",
            "social_protection_registry",
            "household",
            "xlsx",
        ),
        (
            "health-registry-relay.yaml",
            "health_registry",
            "health_facility",
            "parquet",
        ),
    ];

    #[cfg(not(feature = "spdci-api-standards"))]
    let configs = [
        (
            "social-protection-registry-relay.yaml",
            "social_protection_registry",
            "household",
            "xlsx",
        ),
        (
            "health-registry-relay.yaml",
            "health_registry",
            "health_facility",
            "parquet",
        ),
    ];

    for (name, dataset_id, required_entity, expected_format) in configs {
        let path = relay_config(name);
        let loaded = config::load_with_metadata(&path)
            .unwrap_or_else(|err| panic!("{name} failed to load with metadata: {err}"));
        let config = loaded.runtime;

        assert_eq!(config.datasets.len(), 1, "{name}: expected one dataset");
        assert!(
            matches!(config.audit.sink, AuditSinkConfig::Stdout {}),
            "{name}: decentralized Relay demos should use stdout audit"
        );
        assert!(
            config.auth.api_keys.iter().all(|key| key
                .fingerprint
                .name
                .as_deref()
                .is_some_and(|name| name.ends_with("_HASH"))),
            "{name}: Relay credentials should be env-backed fingerprint references only"
        );
        let evidence_only = config
            .auth
            .api_keys
            .iter()
            .find(|key| key.id == "evidence_only")
            .unwrap_or_else(|| panic!("{name}: missing evidence_only principal"));
        assert!(
            evidence_only
                .scopes
                .iter()
                .any(|scope| scope == &format!("{dataset_id}:evidence_verification")),
            "{name}: evidence_only should have evidence verification scope"
        );
        assert!(
            evidence_only
                .scopes
                .iter()
                .all(|scope| !scope.ends_with(":rows") && !scope.ends_with(":aggregate")),
            "{name}: evidence_only must not read rows or aggregates"
        );

        let dataset = config
            .datasets
            .iter()
            .find(|dataset| dataset.id.as_ref() == dataset_id)
            .unwrap_or_else(|| panic!("{name}: missing dataset {dataset_id}"));
        assert!(
            dataset
                .table_configs()
                .any(|table| table.format_name() == Some(expected_format)),
            "{name}: expected a {expected_format} source"
        );
        assert!(
            dataset
                .entities
                .iter()
                .any(|entity| entity.name == required_entity
                    && entity.api.require_purpose_header
                    && !entity.access.evidence_verification_scope.is_empty()),
            "{name}: {required_entity} should require Data-Purpose and expose evidence scope"
        );

        assert_split_metadata_matches_runtime(name, &path, dataset.entities.len());
    }
}

#[cfg(feature = "spdci-api-standards")]
#[test]
fn decentralized_civil_demo_config_enables_dci() {
    seed_demo_secret_env();

    let config =
        config::load(&relay_config("civil-registry-relay.yaml")).expect("civil config loads");
    let spdci = config
        .standards
        .spdci
        .as_ref()
        .expect("civil config should enable SP DCI");
    let crvs = spdci
        .registries
        .get("crvs")
        .expect("civil config should expose a CRVS DCI registry");
    assert_eq!(crvs.dataset.as_ref(), "civil_registry");
    assert_eq!(crvs.entity, "civil_person");
    assert_eq!(
        crvs.identifiers.get("NATIONAL_ID").map(String::as_str),
        Some("national_id")
    );
}

#[test]
fn decentralized_demo_uses_scoped_secret_files() {
    let compose =
        std::fs::read_to_string(decentralized_file("compose.yaml")).expect("compose readable");
    assert!(
        !compose.contains("- .env"),
        "compose must not inject one shared .env into demo services"
    );
    for scoped_env_file in [
        "env/civil-registry-relay.env",
        "env/social-protection-registry-relay.env",
        "env/health-registry-relay.env",
        "env/civil-registry-notary.env",
        "env/social-protection-registry-notary.env",
        "env/shared-eligibility-registry-notary.env",
        "env/demo-client.env",
    ] {
        assert!(
            compose.contains(scoped_env_file),
            "compose should reference scoped env file {scoped_env_file}"
        );
    }

    for (path, issuer_env) in [
        (
            "config/evidence/civil-registry-notary.yaml",
            "CIVIL_EVIDENCE_ISSUER_JWK",
        ),
        (
            "config/evidence/social-protection-registry-notary.yaml",
            "SOCIAL_PROTECTION_EVIDENCE_ISSUER_JWK",
        ),
        (
            "config/evidence/shared-eligibility-registry-notary.yaml",
            "SHARED_ELIGIBILITY_EVIDENCE_ISSUER_JWK",
        ),
    ] {
        let contents =
            std::fs::read_to_string(decentralized_file(path)).expect("notary config readable");
        assert!(
            !contents.contains("REGISTRY_NOTARY_ISSUER_JWK"),
            "{path} must not use the shared issuer key env"
        );
        assert!(
            contents.contains(issuer_env),
            "{path} should use scoped issuer key env {issuer_env}"
        );
    }
}

fn assert_split_metadata_matches_runtime(name: &str, path: &Path, entity_count: usize) {
    let loaded = config::load_with_metadata(path)
        .unwrap_or_else(|err| panic!("{name} split metadata failed to load: {err}"));
    let metadata = loaded.metadata.expect("metadata manifest should compile");
    let dataset = loaded
        .runtime
        .datasets
        .first()
        .expect("decentralized demo config has one dataset");
    let metadata_dataset = metadata
        .dataset(dataset.id.as_ref())
        .unwrap_or_else(|| panic!("{name}: missing metadata dataset {}", dataset.id));
    assert_eq!(
        metadata_dataset.entities.len(),
        entity_count,
        "{name}: metadata entity count should match runtime"
    );
    assert!(
        metadata_dataset
            .evidence_offerings
            .values()
            .next()
            .is_some(),
        "{name}: metadata should advertise at least one Evidence Server offering"
    );
}
