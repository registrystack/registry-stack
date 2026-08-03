// SPDX-License-Identifier: Apache-2.0
//! Real-loader coverage for every maintained operator example once it is staged
//! the way an operator deploys it.
//!
//! `config_schema.rs` only schema-validates the maintained examples in place and
//! `opencrvs_profile.rs` loads a single profile straight out of the repository
//! tree. Neither proves that the pinned artifact closure still resolves once the
//! example is copied into a deployment directory and the example private binding
//! is renamed to the filename an operator actually ships.

use std::fs;
use std::path::{Path, PathBuf};

use registry_relay::config;

/// A maintained operator example and the deployment facts it pins.
struct MaintainedProfile {
    directory: &'static str,
    /// Artifacts the example pins beyond the closure every profile carries.
    extra_artifacts: &'static [&'static str],
    required_environment: &'static [&'static str],
}

const MAINTAINED_PROFILES: &[MaintainedProfile] = &[
    MaintainedProfile {
        directory: "profiles/dhis2-2.41.9-enrollment-status",
        extra_artifacts: &[],
        required_environment: &["DHIS2_USERNAME", "DHIS2_PASSWORD"],
    },
    MaintainedProfile {
        directory: "profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists",
        extra_artifacts: &[],
        required_environment: &["OPENCRVS_DCI_CLIENT_ID", "OPENCRVS_DCI_CLIENT_SECRET"],
    },
    MaintainedProfile {
        directory: "profiles/synthetic-snapshot-exact-person-status",
        extra_artifacts: &["fixtures/people.csv"],
        required_environment: &["REGISTRY_RELAY_CONSULTATION_DATABASE_URL"],
    },
];

const CONFIG_EXAMPLE_FILE: &str = "relay-config.example.yaml";
const EXAMPLE_BINDING_FILE: &str = "private-binding.example.json";
const DEPLOYED_BINDING_FILE: &str = "private-binding.json";

/// The artifact closure every maintained example pins, relative to the profile.
const CLOSURE_ARTIFACTS: &[&str] = &[
    "public-contract.json",
    "integration-pack.json",
    "evidence/conformance.json",
    "evidence/negative-security.json",
    "evidence/minimization.json",
];

/// A maintained operator example copied into a throwaway deployment directory.
///
/// Only the deployment-private binding filename changes; every hash pin in the
/// documented example stays untouched so the loader below catches drift in the
/// maintained baseline rather than in this staging code.
struct StagedProfile {
    /// Held so the staged deployment directory outlives the loader call.
    _directory: tempfile::TempDir,
    config_path: PathBuf,
}

impl StagedProfile {
    fn new(profile: &MaintainedProfile) -> Self {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(profile.directory);
        let directory = tempfile::tempdir().expect("staging directory is creatable");

        for artifact in CLOSURE_ARTIFACTS.iter().chain(profile.extra_artifacts) {
            copy_artifact(
                &source_root.join(artifact),
                &directory.path().join(artifact),
            );
        }
        copy_artifact(
            &source_root.join(EXAMPLE_BINDING_FILE),
            &directory.path().join(DEPLOYED_BINDING_FILE),
        );

        let mut yaml = fs::read_to_string(source_root.join(CONFIG_EXAMPLE_FILE))
            .unwrap_or_else(|_| panic!("the {} example is readable", profile.directory));
        replace_once(
            &mut yaml,
            &format!("path: {EXAMPLE_BINDING_FILE}"),
            &format!("path: {DEPLOYED_BINDING_FILE}"),
            profile.directory,
        );

        let config_path = directory.path().join("relay.yaml");
        fs::write(&config_path, yaml).expect("staged configuration is writable");
        Self {
            _directory: directory,
            config_path,
        }
    }
}

fn copy_artifact(source: &Path, destination: &Path) {
    let parent = destination
        .parent()
        .expect("staged artifact has a parent directory");
    fs::create_dir_all(parent).expect("staged artifact directory is creatable");
    let bytes = fs::read(source)
        .unwrap_or_else(|_| panic!("maintained artifact {} is readable", source.display()));
    fs::write(destination, &bytes).expect("staged artifact is writable");
}

/// Replace `expected` when the example pins it exactly once, so a maintained
/// example that renames or duplicates the anchor fails here instead of silently
/// staging an unchanged document.
fn replace_once(document: &mut String, expected: &str, replacement: &str, profile: &str) {
    assert_eq!(
        document.match_indices(expected).count(),
        1,
        "the {profile} example no longer pins `{expected}` exactly once"
    );
    *document = document.replacen(expected, replacement, 1);
}

#[test]
fn maintained_operator_examples_stage_through_the_real_loader() {
    for profile in MAINTAINED_PROFILES {
        let staged = StagedProfile::new(profile);
        let loaded = config::load_with_metadata(&staged.config_path).unwrap_or_else(|error| {
            panic!(
                "the staged {} operator example did not load: {error}",
                profile.directory
            )
        });
        let consultation = loaded.runtime.consultation.as_ref().unwrap_or_else(|| {
            panic!(
                "the staged {} operator example configured no consultation",
                profile.directory
            )
        });
        let required = consultation.required_environment_references();
        for name in profile.required_environment {
            assert!(
                required.contains(name),
                "the staged {} operator example dropped the {name} environment reference",
                profile.directory
            );
        }
        assert!(
            loaded.consultation_artifacts.is_some(),
            "the staged {} operator example produced no verified artifact closure",
            profile.directory
        );
    }
}
