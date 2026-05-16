// SPDX-License-Identifier: Apache-2.0
//! Focused config-loading verification for the five core demo-pack YAMLs and the
//! combined `all_demos.yaml`. This keeps the public demo pack covered by
//! a focused config-loading check.
//!
//! The core configs declare the same six persona `hash_env:` names
//! (`CATALOG_VIEWER_HASH` etc.), so this binary keeps a single test function
//! that loads them in sequence. Cargo runs each `tests/*.rs` binary in its
//! own process, so the global env writes here cannot race with other tests
//! that use disjoint env names.

use std::env;
use std::path::PathBuf;

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
}
