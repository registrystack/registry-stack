// SPDX-License-Identifier: Apache-2.0
//! Maintained OpenCRVS profile packaging and operator-config checks.

use std::fs;
use std::path::{Path, PathBuf};

use registry_relay::config;

const PROFILE_DIRECTORY: &str = "profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists";

fn profile_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(PROFILE_DIRECTORY)
        .join(name)
}

#[test]
fn maintained_relay_example_loads_the_complete_hash_pinned_closure() {
    let loaded = config::load_with_metadata(&profile_path("relay-config.example.yaml"))
        .expect("maintained OpenCRVS Relay example loads");
    let consultation = loaded
        .runtime
        .consultation
        .as_ref()
        .expect("consultation configured");
    let required = consultation.required_environment_references();
    assert!(required.contains(&"OPENCRVS_DCI_CLIENT_ID"));
    assert!(required.contains(&"OPENCRVS_DCI_CLIENT_SECRET"));
    let _artifacts = loaded
        .consultation_artifacts
        .expect("verified OpenCRVS artifact closure");
}

#[test]
fn public_profile_artifacts_contain_no_live_binding_or_secret_value() {
    for name in [
        "relay-config.example.yaml",
        "private-binding.example.json",
        "integration-pack.json",
        "public-contract.json",
    ] {
        let text = fs::read_to_string(profile_path(name)).expect("profile artifact is readable");
        assert!(!text.contains("client_secret\":"));
        assert!(!text.contains("access_token\":"));
        assert!(!text.contains("OPENCRVS_DCI_SHA_SECRET"));
    }
}
