use std::{collections::BTreeSet, fs, path::Path};

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityMatrix {
    contract: String,
    status: String,
    review_rule: String,
    invariants: Vec<SecurityRow>,
    cross_cutting: serde_norway::Mapping,
    fixture_index: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityRow {
    id: String,
    rule: String,
    threat: String,
    enforcement: String,
    negative_test: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Traceability {
    contract: String,
    entries: Vec<TraceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TraceEntry {
    id: String,
    tests: Vec<TestReference>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestReference {
    file: String,
    name: String,
}

#[test]
fn every_named_security_negative_is_bound_to_an_executable_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let matrix: SecurityMatrix = serde_norway::from_slice(
        &fs::read(root.join("products/evidence/contracts/security-invariant-matrix.yaml"))
            .expect("security matrix reads"),
    )
    .expect("security matrix parses");
    let traceability: Traceability = serde_norway::from_slice(
        &fs::read(root.join("products/evidence/contracts/security-test-traceability.yaml"))
            .expect("traceability reads"),
    )
    .expect("traceability parses");
    assert_eq!(
        traceability.contract,
        "registry.evidence.security-test-traceability/v1"
    );
    assert_eq!(matrix.contract, "registry.evidence.security-invariants/v1");
    assert_eq!(matrix.status, "frozen");
    assert!(matrix.review_rule.contains("named negative test"));
    assert_eq!(
        matrix.fixture_index,
        "../fixtures/conformance/coverage-matrix.yaml"
    );

    let mut required = matrix
        .invariants
        .into_iter()
        .map(|row| {
            assert!(row.id.starts_with("V1-I"));
            assert!(!row.rule.is_empty());
            assert!(!row.threat.is_empty());
            assert!(!row.enforcement.is_empty());
            row.negative_test
        })
        .collect::<BTreeSet<_>>();
    for (_, value) in matrix.cross_cutting {
        let row = value.as_mapping().expect("cross-cutting row is a mapping");
        let id = row
            .get(serde_norway::Value::String("negative_test".to_owned()))
            .and_then(serde_norway::Value::as_str)
            .expect("cross-cutting row names a negative test");
        assert!(required.insert(id.to_owned()), "duplicate matrix id {id}");
    }

    let mut mapped = BTreeSet::new();
    for entry in traceability.entries {
        assert!(
            mapped.insert(entry.id.clone()),
            "duplicate mapping {}",
            entry.id
        );
        assert!(
            !entry.tests.is_empty(),
            "{} has no executable test",
            entry.id
        );
        for test in entry.tests {
            assert!(
                test.file.starts_with("crates/registry-evidence/")
                    && test.file.ends_with(".rs")
                    && !test.file.contains(".."),
                "{} has an unsafe source reference",
                entry.id
            );
            let source = fs::read_to_string(root.join(&test.file))
                .unwrap_or_else(|_| panic!("{} source file is missing", entry.id));
            let signature = format!("fn {}(", test.name);
            assert!(
                source.contains(&signature),
                "{} points to missing Rust test {}",
                entry.id,
                test.name
            );
            let item_start = source
                .find(&signature)
                .expect("test signature was just found");
            let prefix = &source[..item_start];
            let attribute_window = &prefix[prefix.len().saturating_sub(160)..];
            assert!(
                attribute_window.contains("#[test]") || attribute_window.contains("#[tokio::test]"),
                "{} reference {} is not a test item",
                entry.id,
                test.name
            );
        }
    }
    assert_eq!(mapped, required, "security negative-test mapping drifted");
}
