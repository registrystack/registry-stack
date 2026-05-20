// SPDX-License-Identifier: Apache-2.0
//! Focused config-loading verification for the five core demo-pack YAMLs, the
//! combined `all_demos.yaml`, and the full standards demo config. This keeps
//! the public demo pack covered by a focused config-loading check.
//!
//! The core configs declare the same six persona `hash_env:` names
//! (`CATALOG_VIEWER_HASH` etc.), so this binary keeps a single test function
//! that loads them in sequence. Cargo runs each `tests/*.rs` binary in its
//! own process, so the global env writes here cannot race with other tests
//! that use disjoint env names.

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

fn demo_config(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("demo/config")
        .join(name)
}

const PERSONA_HASH_ENVS: &[&str] = &[
    "CATALOG_VIEWER_HASH",
    "PLANNING_ANALYST_HASH",
    "CASEWORK_SYSTEM_HASH",
    "VERIFICATION_SERVICE_HASH",
    "LINKAGE_SERVICE_HASH",
    "OPERATIONS_ADMIN_HASH",
];

#[test]
fn core_demo_configs_load_and_validate() {
    for name in PERSONA_HASH_ENVS {
        env::set_var(name, make_fingerprint(name.as_bytes()));
    }

    let single_dataset_configs = [
        "benefits_casework.yaml",
        "clinic_capacity.yaml",
        "public_works_projects.yaml",
        "education_registry.yaml",
        "subject_registry.yaml",
    ];

    for name in single_dataset_configs {
        let path = demo_config(name);
        let config =
            config::load(&path).unwrap_or_else(|err| panic!("{name} failed to load: {err}"));
        assert_eq!(
            config.datasets.len(),
            1,
            "{name}: expected exactly one dataset"
        );
        assert!(
            matches!(config.audit.sink, AuditSinkConfig::Stdout {}),
            "{name}: single-dataset configs should keep audit on stdout"
        );
        if name == "clinic_capacity.yaml" {
            assert_clinic_facility_spatial_demo(&config);
        }
        assert_split_metadata_matches_runtime(name, &path, config.datasets.len());
    }

    let combined_path = demo_config("all_demos.yaml");
    let combined = config::load(&combined_path).expect("all_demos.yaml failed to load");
    assert_eq!(
        combined.datasets.len(),
        5,
        "all_demos.yaml should aggregate all five datasets"
    );
    let dataset_ids: Vec<&str> = combined.datasets.iter().map(|d| d.id.as_ref()).collect();
    for expected in [
        "benefits_casework",
        "clinic_capacity",
        "public_works_projects",
        "education_registry",
        "subject_registry",
    ] {
        assert!(
            dataset_ids.contains(&expected),
            "all_demos.yaml missing dataset: {expected}"
        );
    }

    match &combined.audit.sink {
        AuditSinkConfig::File { path, .. } => {
            assert_eq!(
                path.to_string_lossy(),
                "demo/var/audit.jsonl",
                "all_demos.yaml should route audit to demo/var/audit.jsonl"
            );
        }
        other => panic!("all_demos.yaml expected file audit sink, got {other:?}"),
    }
    assert_clinic_facility_spatial_demo(&combined);
    assert_split_metadata_matches_runtime(
        "all_demos.yaml",
        &combined_path,
        combined.datasets.len(),
    );
}

fn assert_split_metadata_matches_runtime(name: &str, path: &Path, dataset_count: usize) {
    let loaded = config::load_with_metadata(path)
        .unwrap_or_else(|err| panic!("{name} split metadata failed to load: {err}"));
    let metadata = loaded.metadata.expect("demo metadata manifest");
    assert_eq!(
        metadata.datasets().count(),
        dataset_count,
        "{name}: metadata manifest should describe each runtime dataset"
    );
    for dataset in &loaded.runtime.datasets {
        let metadata_dataset = metadata
            .dataset(dataset.id.as_ref())
            .unwrap_or_else(|| panic!("{name}: missing metadata dataset {}", dataset.id));
        assert_eq!(
            metadata_dataset.entities.len(),
            dataset.entities.len(),
            "{name}: metadata entity count should match runtime for {}",
            dataset.id
        );
    }
}

fn assert_clinic_facility_spatial_demo(config: &config::Config) {
    let clinic = config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_ref() == "clinic_capacity")
        .expect("clinic_capacity dataset is present");
    let facility = clinic
        .entities
        .iter()
        .find(|entity| entity.name == "facility")
        .expect("facility entity is present");
    let spatial = facility
        .spatial
        .as_ref()
        .expect("facility entity should expose an OGC spatial collection");
    assert_eq!(spatial.collection_id.as_deref(), Some("facilities"));
    match &spatial.geometry {
        config::SpatialGeometryConfig::Point {
            longitude_field,
            latitude_field,
            crs,
        } => {
            assert_eq!(longitude_field, "map_longitude");
            assert_eq!(latitude_field, "map_latitude");
            assert_eq!(crs, config::CRS84);
        }
        _ => panic!("clinic facility demo should use point geometry"),
    }
}

#[cfg(all(feature = "spdci-api-standards", feature = "standards-cel-mapping"))]
#[test]
fn spdci_demo_configs_load_and_validate() {
    for name in PERSONA_HASH_ENVS {
        env::set_var(name, make_fingerprint(name.as_bytes()));
    }
    env::set_var(
        "CLAIM_VERIFICATION_BINDING_KEY",
        "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    let demo_dir = demo_config("");
    let mut spdci_configs = Vec::new();
    for entry in std::fs::read_dir(&demo_dir).expect("demo config dir should be readable") {
        let path = entry.expect("demo config entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("yaml") {
            continue;
        }
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".metadata.yaml"))
        {
            continue;
        }
        let contents = std::fs::read_to_string(&path).expect("demo config should be readable");
        if contents.contains("  spdci:") {
            spdci_configs.push(path);
        }
    }
    spdci_configs.sort();

    assert!(
        spdci_configs
            .iter()
            .any(|path| path.file_name().and_then(|name| name.to_str())
                == Some("disability_registry.yaml")),
        "disability_registry.yaml should remain part of the SP DCI demo pack"
    );

    for path in spdci_configs {
        let config = config::load(&path).unwrap_or_else(|err| {
            panic!("{} failed to load: {err}", path.display());
        });
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("demo");
        assert_split_metadata_matches_runtime(name, &path, config.datasets.len());
        let spdci = config
            .standards
            .spdci
            .as_ref()
            .unwrap_or_else(|| panic!("{} should configure SP DCI", path.display()));
        assert!(
            spdci.disability_registry.is_some() || !spdci.registries.is_empty(),
            "{} should declare at least one SP DCI adapter",
            path.display()
        );
    }

    let all_standards_path = demo_config("all_standards.yaml");
    let all_standards =
        config::load(&all_standards_path).expect("all_standards.yaml failed to load");
    assert_eq!(
        all_standards.datasets.len(),
        9,
        "all_standards.yaml should aggregate the five core datasets plus four SP DCI registry datasets"
    );
    assert_clinic_facility_spatial_demo(&all_standards);
    assert!(
        all_standards
            .datasets
            .iter()
            .map(|dataset| dataset.id.as_ref())
            .collect::<Vec<_>>()
            .as_slice()
            .windows(4)
            .any(|window| {
                window
                    == [
                        "disability_registry",
                        "civil_registry",
                        "social_registry",
                        "farmer_registry",
                    ]
            }),
        "all_standards.yaml should keep the SP DCI registry gateway datasets split by domain"
    );
    assert_split_metadata_matches_runtime(
        "all_standards.yaml",
        &all_standards_path,
        all_standards.datasets.len(),
    );
}

#[cfg(all(
    feature = "spdci-api-standards",
    not(feature = "standards-cel-mapping")
))]
#[test]
fn mapped_spdci_demo_configs_require_mapping_feature() {
    for name in PERSONA_HASH_ENVS {
        env::set_var(name, make_fingerprint(name.as_bytes()));
    }
    env::set_var(
        "CLAIM_VERIFICATION_BINDING_KEY",
        "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );

    for name in ["disability_registry.yaml", "all_standards.yaml"] {
        let path = demo_config(name);
        let err = config::load(&path)
            .expect_err("mapped SP DCI demo should require standards-cel-mapping");
        assert_eq!(err.code(), "spdci.config.mapping_feature_disabled");
    }
}
