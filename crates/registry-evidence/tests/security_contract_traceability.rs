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

/// A profile document: any published contract that names its own negative
/// tests. Only the members this checker binds to code and to the traceability
/// index are modelled; the rest of a frozen profile is narrative owned by
/// review. The response and header members belong to the serialization
/// profiles alone, so they are optional here.
#[derive(Deserialize)]
struct Profile {
    contract: String,
    status: String,
    #[serde(default)]
    response: Option<ProfileResponse>,
    #[serde(default)]
    protected_header: Option<ProfileProtectedHeader>,
    negative_tests: Vec<String>,
}

#[derive(Deserialize)]
struct ProfileResponse {
    media_type: String,
}

#[derive(Deserialize)]
struct ProfileProtectedHeader {
    typ: ProfileConst,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileConst {
    #[serde(rename = "const")]
    constant: String,
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

/// Every published profile is checked, not one named file.
///
/// A profile that reaches `frozen` states guarantees adopters rely on, so the
/// negatives it names must resolve in the same security traceability index the
/// checker above proves executable. Binding that to a hardcoded path meant a
/// new profile could name any negative it liked and every gate stayed green,
/// so this walks the published contract directory instead.
///
/// The security index owns the `sec-` identifiers, and those are what a frozen
/// profile must have mapped. A profile may also name conformance case
/// identifiers, which live in the fixture corpus and are not this index's to
/// resolve. A `draft` profile is exempt, because declaring guarantees before
/// the tests exist is exactly what draft records; the floor below is what stops
/// a status downgrade being used to dodge the gate.
///
/// The serialization profiles additionally cannot drift away from the media
/// type and JWT type the runtime actually emits.
#[test]
fn every_frozen_profile_negative_is_bound_to_a_mapped_security_negative() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let contracts = root.join("products/evidence/contracts");
    let traceability: Traceability = serde_norway::from_slice(
        &fs::read(contracts.join("security-test-traceability.yaml")).expect("traceability reads"),
    )
    .expect("traceability parses");
    let mapped = traceability
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<BTreeSet<_>>();

    // The serialization each profile documents, against the constants the
    // runtime emits from.
    let serializations = BTreeMap::from([
        (
            "registry.evidence.jws-profile/v1",
            (
                registry_evidence::EVIDENCE_JWS_MEDIA_TYPE,
                registry_evidence::EVIDENCE_JWS_TYP,
            ),
        ),
        (
            "registry.evidence.sd-jwt-vc-profile/v1",
            (
                registry_evidence::EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
                registry_evidence::EVIDENCE_SD_JWT_VC_TYP,
            ),
        ),
    ]);

    let mut documents = fs::read_dir(&contracts)
        .expect("published contract directory reads")
        .map(|entry| entry.expect("contract directory entry reads").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect::<Vec<_>>();
    documents.sort();
    assert!(!documents.is_empty(), "no published contract was read");

    let mut checked = BTreeSet::new();
    for path in documents {
        let bytes = fs::read(&path).unwrap_or_else(|_| panic!("{} reads", path.display()));
        let document: serde_norway::Value = serde_norway::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("{} parses", path.display()));
        if document
            .get(serde_norway::Value::String("negative_tests".to_owned()))
            .is_none()
        {
            continue;
        }
        let profile: Profile = serde_norway::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("{} is not a profile document", path.display()));
        assert!(
            matches!(profile.status.as_str(), "draft" | "frozen"),
            "{} carries an unreviewed status {}",
            path.display(),
            profile.status
        );
        assert!(
            !profile.negative_tests.is_empty(),
            "{} names no negative test",
            path.display()
        );

        if let Some((media_type, typ)) = serializations.get(profile.contract.as_str()) {
            let response = profile
                .response
                .as_ref()
                .unwrap_or_else(|| panic!("{} documents no response", profile.contract));
            let header = profile
                .protected_header
                .as_ref()
                .unwrap_or_else(|| panic!("{} documents no protected header", profile.contract));
            assert_eq!(&response.media_type, media_type, "{}", profile.contract);
            assert_eq!(&header.typ.constant, typ, "{}", profile.contract);
        }

        let mut named = BTreeSet::new();
        for id in &profile.negative_tests {
            assert!(
                named.insert(id.clone()),
                "{} repeats {id}",
                profile.contract
            );
            if profile.status == "frozen" && id.starts_with("sec-") {
                assert!(
                    mapped.contains(id),
                    "{} negative {id} is not mapped to an executable test",
                    profile.contract
                );
            }
        }
        if profile.status == "frozen" {
            checked.insert(profile.contract);
        }
    }

    // The floor. These profiles are frozen today, so a rename, a move, or a
    // quiet downgrade to draft fails here rather than silently dropping the
    // guarantees they already publish.
    for required in [
        "registry.evidence.jws-profile/v1",
        "registry.evidence.sd-jwt-vc-profile/v1",
        "registry.evidence.holder-bound-profile/v1",
        "registry.evidence.oid4vci-profile/v1",
    ] {
        assert!(
            checked.contains(required),
            "{required} stopped being checked as a frozen profile"
        );
    }
}

/// Prove that one mapped reference still names a real Rust test item, so a
/// renamed, moved, or deleted test fails the traceability checker.
fn assert_reference_is_an_executable_test(root: &Path, entry_id: &str, test: &TestReference) {
    // Evidence security invariants may be implemented by the runtime, its
    // relying-party client, the portable verifier, the narrowly shared
    // platform primitives they use, or the OpenID4VCI delivery front end,
    // which owns the wallet-facing boundary the runtime deliberately does not
    // speak. The front end is a permitted implementer of its own delivery
    // negatives only; a delivery negative proven in a shared primitive rather
    // than at the endpoint would not be traceable here, which is the point.
    let permitted_crate = [
        "crates/registry-evidence/",
        "crates/registry-evidence-client/",
        "crates/registry-evidence-verifier/",
        "crates/registry-evidence-oid4vci/",
        "crates/registry-platform-audit/",
        "crates/registry-platform-config/",
        "crates/registry-platform-crypto/",
    ]
    .iter()
    .any(|prefix| test.file.starts_with(prefix));
    assert!(
        permitted_crate && test.file.ends_with(".rs") && !test.file.contains(".."),
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
    // The parenthesized form is a test item too. A concurrency invariant can
    // only be proven by a test that actually runs on several threads, so
    // `#[tokio::test(flavor = "multi_thread", ...)]` has to be traceable.
    assert!(
        attribute_window.contains("#[test]")
            || attribute_window.contains("#[tokio::test]")
            || attribute_window.contains("#[tokio::test("),
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

    let expected = (1..=84)
        .map(|row| format!("acceptance-row-{row:02}"))
        .collect::<Vec<_>>();
    let mapped = traceability
        .entries
        .iter()
        .map(|entry| entry.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        mapped, expected,
        "acceptance row mapping is not the 84 required rows in order"
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

/// Every document in the published contract directory is YAML, but only a few
/// of them are parsed by a test, so a document that stops parsing stays
/// tracked, reviewed, and quoted while no longer being readable by a machine.
/// Parse the whole directory rather than the documents that happen to have a
/// consumer.
#[test]
fn every_published_contract_document_parses_as_yaml() {
    let contracts = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/contracts");
    let mut documents: Vec<_> = fs::read_dir(&contracts)
        .expect("contract directory reads")
        .map(|entry| entry.expect("contract entry reads").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .collect();
    documents.sort();
    assert!(
        !documents.is_empty(),
        "{} holds no contract document, so this check would pass vacuously",
        contracts.display()
    );
    for document in documents {
        let bytes = fs::read(&document).expect("contract document reads");
        if let Err(error) = serde_norway::from_slice::<serde_norway::Value>(&bytes) {
            panic!("{} is not parseable YAML: {error}", document.display());
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
