// SPDX-License-Identifier: Apache-2.0

#[path = "../build_support.rs"]
mod build_support;

use std::fs;
use std::path::Path;

#[test]
fn custom_feature_profile_must_match_cargo_effective_features() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let declared = build_support::declared_feature_names(&manifest).unwrap();
    let enabled = vec![
        "attribute-release".to_string(),
        "crosswalk-runtime".to_string(),
    ];

    assert!(build_support::validate_requested_profile(
        "attribute-release,crosswalk-runtime",
        &declared,
        &enabled,
    )
    .is_ok());
    let incomplete =
        build_support::validate_requested_profile("attribute-release", &declared, &enabled)
            .unwrap_err();
    assert!(incomplete.contains("missing: [crosswalk-runtime]"));
    let unordered = build_support::validate_requested_profile(
        "crosswalk-runtime,attribute-release",
        &declared,
        &enabled,
    )
    .unwrap_err();
    assert!(unordered.contains("canonical order"));
}

#[test]
fn compiled_feature_inventory_comes_from_cargo_manifest() {
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let declared = build_support::declared_feature_names(&manifest).unwrap();
    assert!(registry_relay::compiled_cargo_features()
        .iter()
        .all(|feature| declared.iter().any(|declared| declared == feature)));
}
