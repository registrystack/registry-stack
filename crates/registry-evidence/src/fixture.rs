// SPDX-License-Identifier: Apache-2.0
//! The Evidence fixture format: one `fixtures/*.yaml` file of a bundle, the
//! synthetic cases a requirement is proven against offline.
//!
//! The bundle loader reads each referenced fixture through the shared
//! configuration reader and checks that it is synthetic and covers every
//! required case category. The offline runner interprets the cases. Every
//! refusal names the file, the member, its line and column, and the fix, and
//! none repeats a value from the file (CFG-SEC-3).

use std::collections::BTreeSet;

use registry_platform_yaml::{
    ApiVersion, Document, EnvelopeRule, Expect, FormatSpec, Reader, RemovedKey, Report, Severity,
};
use serde_json::Value;

use crate::config::BundleExpressions;

/// The kind of an Evidence fixture document.
pub const EVIDENCE_FIXTURE_KIND: &str = "EvidenceFixture";

/// The current `apiVersion` of the Evidence fixture format.
pub const EVIDENCE_FIXTURE_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/fixture/v1alpha1";

/// The Evidence fixture format.
pub const EVIDENCE_FIXTURE_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: EVIDENCE_FIXTURE_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(EVIDENCE_FIXTURE_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[RemovedKey {
        pointer: "/fixture",
        replacement: "The fixture identifier is replaced by the envelope: remove `fixture` and declare `apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1` and `kind: EvidenceFixture`.",
    }],
};

/// The most cases one fixture holds.
const MAXIMUM_CASES: usize = 256;

/// The most bytes of one case identifier.
const MAXIMUM_CASE_ID_BYTES: usize = 128;

/// Read one fixture file and check that it is synthetic and covers every
/// case category. `file` is the name the diagnostics carry.
/// `declared_unresolved` says whether the requirement's initial source
/// declares an unresolved outcome a case may replay.
///
/// The value returned is the document without its envelope, for the offline
/// runner.
pub fn read_fixture(file: &str, bytes: &[u8], declared_unresolved: bool) -> Result<Value, Report> {
    let mut hook = BundleExpressions;
    let document = Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(&EVIDENCE_FIXTURE_FORMAT))?;
    let mut value = document.to_json_value();
    check_coverage(&document, &value, declared_unresolved)
        .map_err(|diagnostic| Report::new(vec![*diagnostic]))?;
    if let Some(body) = value.as_object_mut() {
        body.remove("apiVersion");
        body.remove("kind");
    }
    Ok(value)
}

type Refusal = Box<registry_platform_yaml::Diagnostic>;

fn check_coverage(
    document: &Document,
    root: &Value,
    declared_unresolved: bool,
) -> Result<(), Refusal> {
    // A member the rule concerns that is not written is placed at the
    // nearest member that is.
    let refuse = |code: &str, pointer: &str, message: &str, action: &str| -> Refusal {
        let mut written = pointer;
        while document.span_of(written).is_none() {
            written = written.rsplit_once('/').map_or("", |(parent, _)| parent);
        }
        let mut diagnostic =
            document.diagnostic_at_value(Severity::Error, code, written, message, action);
        diagnostic.path = pointer.to_owned();
        Box::new(diagnostic)
    };
    if root.get("synthetic_only") != Some(&Value::Bool(true)) {
        return Err(refuse(
            "evidence.fixture.not-synthetic",
            "/synthetic_only",
            "a fixture declares synthetic_only: true",
            "Declare `synthetic_only: true` and use invented values only.",
        ));
    }
    let Some(cases) = root.get("cases").and_then(Value::as_array) else {
        return Err(refuse(
            "evidence.fixture.missing-cases",
            "/cases",
            "a fixture declares its cases as a list",
            "Declare `cases` as a list of cases, each with an `id`.",
        ));
    };
    if cases.is_empty() || cases.len() > MAXIMUM_CASES {
        return Err(refuse(
            "evidence.fixture.invalid-case-count",
            "/cases",
            "a fixture holds from 1 to 256 cases",
            "Declare at least one case, and split a longer fixture between requirements.",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut categories = Categories::default();
    for (index, case) in cases.iter().enumerate() {
        let Some(id) = case.get("id").and_then(Value::as_str) else {
            return Err(refuse(
                "evidence.fixture.invalid-case",
                &format!("/cases/{index}/id"),
                "a fixture case is a mapping with a text id",
                "Write the case as a mapping and give it an `id`.",
            ));
        };
        if id.is_empty() || id.len() > MAXIMUM_CASE_ID_BYTES || !ids.insert(id) {
            return Err(refuse(
                "evidence.fixture.invalid-case-id",
                &format!("/cases/{index}/id"),
                "a case id is 1 to 128 bytes and unique within its fixture",
                "Give every case a short id no other case of this fixture uses.",
            ));
        }
        let pointer = format!("/cases/{index}/declaredUnresolved");
        let case_declares_unresolved = match case.get("declaredUnresolved") {
            Some(Value::Bool(true)) if declared_unresolved => true,
            Some(Value::Bool(true)) => {
                return Err(refuse(
                    "evidence.fixture.unresolved-not-declared",
                    &pointer,
                    "a case replays declaredUnresolved, but the requirement's initial source declares no unresolved outcome",
                    "Remove `declaredUnresolved`, or declare the unresolved outcome on the source.",
                ));
            }
            Some(_) => {
                return Err(refuse(
                    "evidence.fixture.invalid-unresolved-marker",
                    &pointer,
                    "declaredUnresolved is written as true or not at all",
                    "Write `declaredUnresolved: true`, or remove it.",
                ));
            }
            None => false,
        };
        categories.observe(id, case_declares_unresolved);
    }
    if !categories.complete() {
        return Err(refuse(
            "evidence.fixture.incomplete-coverage",
            "/cases",
            "the cases do not cover every required category",
            "Add the missing cases: positive, negative*, boundary*, missing*, no-match, ambiguous*, source-failure, and anti-reconstruction.",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Categories {
    positive: bool,
    negative: bool,
    boundary: bool,
    missing: bool,
    no_match: bool,
    ambiguous: bool,
    source_failure: bool,
    anti_reconstruction: bool,
}

impl Categories {
    fn observe(&mut self, id: &str, declared_unresolved: bool) {
        self.positive |= id == "positive";
        self.negative |= id.starts_with("negative");
        self.boundary |= id.starts_with("boundary");
        self.missing |= id.starts_with("missing");
        self.no_match |= id == "no-match";
        self.ambiguous |= id.starts_with("ambiguous");
        // The configured source has already collapsed its hidden no-match and
        // ambiguous states into one exact transport outcome. Evidence cannot
        // truthfully label the fixture as either branch, so the neutral case
        // proves the public behavior shared by both completeness categories.
        self.no_match |= declared_unresolved;
        self.ambiguous |= declared_unresolved;
        self.source_failure |= id == "source-failure";
        self.anti_reconstruction |= id == "anti-reconstruction";
    }

    fn complete(&self) -> bool {
        self.positive
            && self.negative
            && self.boundary
            && self.missing
            && self.no_match
            && self.ambiguous
            && self.source_failure
            && self.anti_reconstruction
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY-fixture-91c2";

    const HEADER: &str =
        "apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1\nkind: EvidenceFixture\n";

    fn complete_cases() -> String {
        [
            "positive",
            "negative-false",
            "boundary-on",
            "missing-fact",
            "no-match",
            "ambiguous",
            "source-failure",
            "anti-reconstruction",
        ]
        .iter()
        .map(|id| format!("  - {{id: {id}}}\n"))
        .collect()
    }

    fn refusal(text: &str, declared_unresolved: bool) -> registry_platform_yaml::Diagnostic {
        let report = read_fixture("fixtures/cases.yaml", text.as_bytes(), declared_unresolved)
            .expect_err("the fixture is refused");
        assert!(
            !report.render_human().contains(CANARY),
            "the refusal repeats no value"
        );
        assert_eq!(report.diagnostics().len(), 1, "one diagnostic");
        report.diagnostics()[0].clone()
    }

    #[test]
    fn reads_a_complete_fixture_without_its_envelope() {
        let text = format!("{HEADER}synthetic_only: true\ncases:\n{}", complete_cases());
        let value = read_fixture("fixtures/cases.yaml", text.as_bytes(), false)
            .expect("a complete fixture");
        assert_eq!(value.get("apiVersion"), None);
        assert_eq!(value.get("kind"), None);
        assert_eq!(value["cases"].as_array().map(Vec::len), Some(8));
    }

    #[test]
    fn a_retired_header_without_the_envelope_is_refused_and_named() {
        let text = format!(
            "fixture: registry.evidence.reference.{CANARY}/v1\nsynthetic_only: true\ncases:\n{}",
            complete_cases()
        );
        let report = read_fixture("fixtures/cases.yaml", text.as_bytes(), false)
            .expect_err("the fixture is refused");
        assert!(
            !report.render_human().contains(CANARY),
            "the refusal repeats no value"
        );
        let refusals: Vec<(&str, &str)> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            refusals,
            [
                ("config.missing-envelope", ""),
                ("config.removed-key", "/fixture")
            ]
        );
    }

    #[test]
    fn refuses_each_rule_at_its_member_without_the_value() {
        let cases = complete_cases();
        let without_ambiguous = cases.replace("  - {id: ambiguous}\n", "");
        let table: Vec<(&str, String, bool, &str, &str, usize)> = vec![
            (
                "retired identifier beside the envelope",
                format!("{HEADER}fixture: registry.evidence.reference.{CANARY}/v1\nsynthetic_only: true\ncases:\n{cases}"),
                false,
                "config.removed-key",
                "/fixture",
                3,
            ),
            (
                "not synthetic",
                format!("{HEADER}synthetic_only: false\ncases:\n{cases}"),
                false,
                "evidence.fixture.not-synthetic",
                "/synthetic_only",
                3,
            ),
            (
                "cases not a list",
                format!("{HEADER}synthetic_only: true\ncases: {CANARY}\n"),
                false,
                "evidence.fixture.missing-cases",
                "/cases",
                4,
            ),
            (
                "repeated case id",
                format!("{HEADER}synthetic_only: true\ncases:\n{cases}  - {{id: positive}}\n"),
                false,
                "evidence.fixture.invalid-case-id",
                "/cases/8/id",
                13,
            ),
            (
                "unresolved without a source declaration",
                format!("{HEADER}synthetic_only: true\ncases:\n{without_ambiguous}  - {{id: unresolved, declaredUnresolved: true}}\n"),
                false,
                "evidence.fixture.unresolved-not-declared",
                "/cases/7/declaredUnresolved",
                12,
            ),
            (
                "unresolved marker not true",
                format!("{HEADER}synthetic_only: true\ncases:\n{without_ambiguous}  - {{id: unresolved, declaredUnresolved: false}}\n"),
                true,
                "evidence.fixture.invalid-unresolved-marker",
                "/cases/7/declaredUnresolved",
                12,
            ),
            (
                "incomplete coverage",
                format!("{HEADER}synthetic_only: true\ncases:\n{without_ambiguous}"),
                false,
                "evidence.fixture.incomplete-coverage",
                "/cases",
                5,
            ),
        ];
        for (label, text, declared_unresolved, code, path, line) in table {
            let diagnostic = refusal(&text, declared_unresolved);
            assert_eq!(diagnostic.code, code, "{label}");
            assert_eq!(diagnostic.path, path, "{label}");
            let source = diagnostic.source.as_ref().expect("a positioned diagnostic");
            assert_eq!(source.line, Some(line), "{label}");
        }
    }

    #[test]
    fn declared_unresolved_fixture_neutrally_covers_hidden_lookup_categories() {
        let cases = complete_cases()
            .replace("  - {id: no-match}\n", "")
            .replace("  - {id: ambiguous}\n", "");
        let fixture = |marker: &str| {
            format!(
                "{HEADER}synthetic_only: true\ncases:\n{cases}  - {{id: unresolved, declaredUnresolved: {marker}}}\n"
            )
        };
        read_fixture("fixtures/cases.yaml", fixture("true").as_bytes(), true)
            .expect("the declared unresolved case covers no-match and ambiguity");

        // The marker counts only when the requirement declares the collapse,
        // and only as `true`; either other way the hidden categories stay
        // uncovered.
        for (marker, declared, code) in [
            ("true", false, "evidence.fixture.unresolved-not-declared"),
            ("false", true, "evidence.fixture.invalid-unresolved-marker"),
        ] {
            let report = read_fixture("fixtures/cases.yaml", fixture(marker).as_bytes(), declared)
                .expect_err("the hidden lookup categories stay uncovered");
            assert!(
                report
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == code),
                "{code}"
            );
        }
    }
}
