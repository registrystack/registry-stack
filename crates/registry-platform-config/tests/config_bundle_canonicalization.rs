use std::path::PathBuf;

use registry_platform_crypto::canonicalize_json;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/config_bundle/canonicalization")
        .join(name)
}

#[test]
fn canonical_manifest_golden_vectors_match() {
    let input =
        std::fs::read(fixture_path("manifest-non-ascii-nested.input.json")).expect("input fixture");
    let expected =
        std::fs::read_to_string(fixture_path("manifest-non-ascii-nested.canonical.json"))
            .expect("canonical fixture");
    let value: serde_json::Value = serde_json::from_slice(&input).expect("input json");

    let canonical = canonicalize_json(&value).expect("canonical json");

    let canonical = std::str::from_utf8(&canonical).expect("canonical utf8");
    assert_eq!(canonical, expected.trim_end_matches('\n'));
}
