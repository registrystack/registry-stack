// SPDX-License-Identifier: Apache-2.0

mod build_support;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=REGISTRY_RELAY_FEATURES");

    let manifest =
        fs::read_to_string("Cargo.toml").expect("registry-relay Cargo.toml must be readable");
    let declared = build_support::declared_feature_names(&manifest)
        .expect("registry-relay Cargo features must be readable");
    let mut enabled = declared
        .iter()
        .filter(|feature| {
            let environment_name =
                format!("CARGO_FEATURE_{}", feature.replace('-', "_").to_uppercase());
            env::var_os(environment_name).is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    enabled.sort();

    if let Ok(requested) = env::var("REGISTRY_RELAY_FEATURES") {
        build_support::validate_requested_profile(&requested, &declared, &enabled)
            .unwrap_or_else(|error| panic!("invalid Registry Relay feature profile: {error}"));
    }

    let generated = format!(
        "const COMPILED_CARGO_FEATURES: &[&str] = &[\n{}\n];\n",
        enabled
            .iter()
            .map(|feature| format!("    {feature:?},"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR"))
        .join("compiled_cargo_features.rs");
    fs::write(output, generated).expect("compiled feature inventory must be writable");
}
