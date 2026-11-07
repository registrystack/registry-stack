//! The Unicode data version constant must move with the ICU pin.

use registry_platform_text::{ICU_VERSION_PIN, UNICODE_DATA_VERSION, UNICODE_VERSION};
use std::path::PathBuf;

fn repository_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

/// The `version = "..."` of a root `[workspace.dependencies]` entry.
fn workspace_pin(manifest: &str, name: &str) -> String {
    let prefix = format!("{name} = ");
    let line = manifest
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no workspace dependency {name}"));
    let after = line.split("version = \"").nth(1).expect("a version key");
    after.split('"').next().expect("closing quote").to_owned()
}

#[test]
fn icu_pins_match_the_constant() {
    let manifest = repository_file("Cargo.toml");
    for name in ["icu_casemap", "icu_normalizer", "icu_properties"] {
        assert_eq!(
            workspace_pin(&manifest, name),
            ICU_VERSION_PIN,
            "{name} pin moved: review the Unicode data version and update the constants in registry-platform-text"
        );
    }
}

#[test]
fn locked_icu_data_crates_match_the_pin() {
    let lock = repository_file("Cargo.lock");
    let minor = ICU_VERSION_PIN.trim_start_matches('~');
    let minor = minor.rsplit_once('.').expect("major.minor.patch").0;
    for name in [
        "icu_casemap_data",
        "icu_normalizer_data",
        "icu_properties_data",
    ] {
        let header = format!("name = \"{name}\"\nversion = \"");
        let version = lock
            .split(&header)
            .nth(1)
            .unwrap_or_else(|| panic!("{name} missing from Cargo.lock"))
            .split('"')
            .next()
            .unwrap();
        assert!(
            version.starts_with(&format!("{minor}.")),
            "{name} locked at {version}, pin is {ICU_VERSION_PIN}: update the Unicode data version"
        );
    }
}

#[test]
fn data_version_is_derived_from_the_pin() {
    assert_eq!(
        UNICODE_DATA_VERSION,
        format!("icu4x{ICU_VERSION_PIN}/unicode-{UNICODE_VERSION}")
    );
}
