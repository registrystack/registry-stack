use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceTraceability {
    contract: String,
    entries: Vec<AcceptanceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceEntry {
    id: String,
    summary: String,
    tests: Vec<TestReference>,
    /// Names the residual gap when executable tests only partially prove a row.
    #[serde(default)]
    note: Option<String>,
}

/// The conformance coverage index. Only the fields consumed by this checker are
/// modelled; the index carries further frozen sections owned by other tests.
#[derive(Deserialize)]
struct CoverageIndex {
    categories: Vec<String>,
    acceptance_definitions: Vec<CoverageDefinition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageDefinition {
    definition: String,
    bundle: String,
    cases: String,
    selector: String,
    posture: String,
    supported_values: Vec<String>,
    coverage: BTreeMap<String, serde_norway::Value>,
}

#[derive(Deserialize)]
struct CasesFixture {
    cases: Vec<CaseEntry>,
}

#[derive(Deserialize)]
struct CaseEntry {
    id: String,
    /// A companion bundle name is how an anti-reconstruction case is addressed
    /// by the coverage index, because the case itself is a bundle rejection.
    #[serde(default)]
    companion_bundle: Option<String>,
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
        for test in &entry.tests {
            assert_reference_is_an_executable_test(&root, &entry.id, test);
        }
    }
    assert_eq!(mapped, required, "security negative-test mapping drifted");
}

/// Prove that one mapped reference still names a real Rust test item, so a
/// renamed, moved, or deleted test fails the traceability checker.
fn assert_reference_is_an_executable_test(root: &Path, entry_id: &str, test: &TestReference) {
    assert!(
        test.file.starts_with("crates/registry-evidence/")
            && test.file.ends_with(".rs")
            && !test.file.contains(".."),
        "{entry_id} has an unsafe source reference"
    );
    let source = fs::read_to_string(root.join(&test.file))
        .unwrap_or_else(|_| panic!("{entry_id} source file is missing"));
    let signature = format!("fn {}(", test.name);
    assert!(
        source.contains(&signature),
        "{entry_id} points to missing Rust test {}",
        test.name
    );
    let item_start = source
        .find(&signature)
        .expect("test signature was just found");
    let prefix = &source[..item_start];
    let attribute_window = &prefix[prefix.len().saturating_sub(160)..];
    assert!(
        attribute_window.contains("#[test]") || attribute_window.contains("#[tokio::test]"),
        "{entry_id} reference {} is not a test item",
        test.name
    );
}

#[test]
fn every_acceptance_row_is_bound_to_an_executable_test() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let traceability: AcceptanceTraceability = serde_norway::from_slice(
        &fs::read(root.join("products/evidence/contracts/acceptance-test-traceability.yaml"))
            .expect("acceptance traceability reads"),
    )
    .expect("acceptance traceability parses");
    assert_eq!(
        traceability.contract,
        "registry.evidence.acceptance-test-traceability/v1"
    );

    let expected = (1..=62)
        .map(|row| format!("acceptance-row-{row:02}"))
        .collect::<Vec<_>>();
    let mapped = traceability
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        mapped, expected,
        "acceptance row mapping is not the 62 required rows in order"
    );

    for entry in &traceability.entries {
        assert!(
            !entry.summary.trim().is_empty(),
            "{} has no summary",
            entry.id
        );
        if let Some(note) = &entry.note {
            assert!(
                !note.trim().is_empty(),
                "{} has an empty residual-gap note",
                entry.id
            );
        }
        assert!(
            !entry.tests.is_empty(),
            "{} has no executable test",
            entry.id
        );
        let mut referenced = BTreeSet::new();
        for test in &entry.tests {
            assert!(
                referenced.insert((test.file.as_str(), test.name.as_str())),
                "{} repeats the reference {}",
                entry.id,
                test.name
            );
            assert_reference_is_an_executable_test(&root, &entry.id, test);
        }
    }

    assert_coverage_index_resolves(&root);
}

/// The conformance coverage index is an input to acceptance traceability: every
/// acceptance definition must still point at real bundle and case artifacts,
/// and every case named by a coverage category must still exist in them.
fn assert_coverage_index_resolves(root: &Path) {
    let fixtures = root.join("products/evidence/fixtures");
    let index: CoverageIndex = serde_norway::from_slice(
        &fs::read(fixtures.join("conformance/coverage-matrix.yaml")).expect("coverage index reads"),
    )
    .expect("coverage index parses");
    let categories = index
        .categories
        .iter()
        .cloned()
        .collect::<BTreeSet<String>>();
    assert_eq!(
        categories.len(),
        index.categories.len(),
        "coverage index repeats a category"
    );
    assert!(
        !index.acceptance_definitions.is_empty(),
        "coverage index names no acceptance definition"
    );

    let mut seen = BTreeSet::new();
    for definition in &index.acceptance_definitions {
        assert!(
            seen.insert(definition.definition.clone()),
            "coverage index repeats definition {}",
            definition.definition
        );
        assert!(
            !definition.selector.is_empty()
                && !definition.posture.is_empty()
                && !definition.supported_values.is_empty(),
            "{} has an incomplete coverage declaration",
            definition.definition
        );
        assert!(
            fixture_path(&fixtures, &definition.definition, &definition.bundle).is_file(),
            "{} names a missing bundle {}",
            definition.definition,
            definition.bundle
        );
        let cases_path = fixture_path(&fixtures, &definition.definition, &definition.cases);
        let cases: CasesFixture =
            serde_norway::from_slice(&fs::read(&cases_path).unwrap_or_else(|_| {
                panic!("{} names a missing case fixture", definition.definition)
            }))
            .unwrap_or_else(|_| panic!("{} case fixture parses", definition.definition));

        let mut addressable = BTreeSet::new();
        for case in &cases.cases {
            addressable.insert(case.id.clone());
            if let Some(companion) = &case.companion_bundle {
                addressable.insert(companion.clone());
            }
        }
        assert_eq!(
            definition.coverage.keys().cloned().collect::<BTreeSet<_>>(),
            categories,
            "{} does not cover exactly the declared categories",
            definition.definition
        );
        for (category, named) in &definition.coverage {
            let names = match named {
                serde_norway::Value::String(one) => vec![one.as_str()],
                serde_norway::Value::Sequence(many) => many
                    .iter()
                    .map(|value| {
                        value.as_str().unwrap_or_else(|| {
                            panic!(
                                "{}/{category} names a non-string case",
                                definition.definition
                            )
                        })
                    })
                    .collect(),
                _ => panic!(
                    "{}/{category} is neither one case nor a case list",
                    definition.definition
                ),
            };
            assert!(
                !names.is_empty(),
                "{}/{category} names no case",
                definition.definition
            );
            for name in names {
                assert!(
                    addressable.contains(name),
                    "{}/{category} names {name}, which is absent from {}",
                    definition.definition,
                    cases_path.display()
                );
            }
        }
    }
}

/// Resolve one coverage-index path, which is written relative to the
/// `conformance` directory, without allowing it to escape the fixture tree.
fn fixture_path(fixtures: &Path, definition: &str, relative: &str) -> std::path::PathBuf {
    let inside = relative
        .strip_prefix("../")
        .unwrap_or_else(|| panic!("{definition} path {relative} is not fixture-relative"));
    assert!(
        inside.ends_with(".yaml") && !inside.contains("..") && !inside.starts_with('/'),
        "{definition} path {relative} is unsafe"
    );
    fixtures.join(inside)
}
