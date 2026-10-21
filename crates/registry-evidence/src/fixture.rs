// SPDX-License-Identifier: Apache-2.0
//! The Evidence fixture format: one `fixtures/*.yaml` file of a bundle, the
//! synthetic cases a requirement is proven against offline.
//!
//! The bundle loader reads each referenced fixture through the shared
//! configuration reader and checks that it is synthetic. Production and
//! evidence-grade bundles also require every case category. The offline runner interprets the cases. Every
//! refusal names the file, the member, its line and column, and the fix, and
//! none repeats a value from the file (CFG-SEC-3).

use registry_platform_yaml::{
    local_id_collision_diagnostics, ApiVersion, AuthoredId, Document, EnvelopeRule, Expect,
    FormatSpec, Reader, RemovedKey, Report, Severity,
};
use serde_json::Value;

use crate::config::{AssuranceProfile, BundleExpressions};

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
    removed_keys: &[
        RemovedKey {
            pointer: "/fixture",
            replacement: "The fixture identifier is replaced by the envelope: remove `fixture` and declare `apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1` and `kind: EvidenceFixture`.",
        },
        RemovedKey { pointer: "/synthetic_only", replacement: "Write `syntheticOnly` instead." },
        RemovedKey { pointer: "/coequal_acceptance_definition", replacement: "Write `coequalAcceptanceDefinition` instead." },
        RemovedKey { pointer: "/provider_contract", replacement: "Write `providerContract` instead." },
        RemovedKey { pointer: "/privacy_expectation", replacement: "Write `privacyExpectation` instead." },
        RemovedKey { pointer: "/common/observed_at", replacement: "Write `observedAt` instead." },
        RemovedKey { pointer: "/common/legal_local_date", replacement: "Write `legalLocalDate` instead." },
        RemovedKey { pointer: "/common/verified_token_claims", replacement: "Write `verifiedTokenClaims` instead." },
        RemovedKey { pointer: "/cases/*/observed_at", replacement: "Write `observedAt` instead." },
        RemovedKey { pointer: "/cases/*/legal_local_date", replacement: "Write `legalLocalDate` instead." },
        RemovedKey { pointer: "/cases/*/verified_token_claims", replacement: "Write `verifiedTokenClaims` instead." },
        RemovedKey { pointer: "/cases/*/expected_lookup", replacement: "Write `expectedLookup` instead." },
        RemovedKey { pointer: "/cases/*/expected_public_problem", replacement: "Write `expectedPublicProblem` instead." },
        RemovedKey { pointer: "/cases/*/expected_subject_roles", replacement: "Write `expectedSubjectRoles` instead." },
        RemovedKey { pointer: "/cases/*/derivation_runs", replacement: "Write `derivationRuns` instead." },
        RemovedKey { pointer: "/cases/*/signed_success", replacement: "Write `signedSuccess` instead." },
        RemovedKey { pointer: "/cases/*/source_failure", replacement: "Write `sourceFailure` instead." },
        RemovedKey { pointer: "/cases/*/companion_bundle", replacement: "Write `companionBundle` instead." },
        RemovedKey { pointer: "/cases/*/injected_derivation", replacement: "Write `injectedDerivation` instead." },
        RemovedKey { pointer: "/cases/*/expected_value", replacement: "Write `expectedValue` instead." },
        RemovedKey { pointer: "/cases/*/expected_values", replacement: "Write `expectedValues` instead." },
        RemovedKey { pointer: "/privacyExpectation/evidence_contains", replacement: "Write `evidenceContains` instead." },
        RemovedKey { pointer: "/privacyExpectation/evidence_excludes", replacement: "Write `evidenceExcludes` instead." },
        RemovedKey { pointer: "/privacyExpectation/diagnostics_exclude", replacement: "Write `diagnosticsExclude` instead." },
        RemovedKey { pointer: "/privacyExpectation/member_inputs", replacement: "Write `memberInputs` instead." },
        RemovedKey { pointer: "/privacyExpectation/minimization_claim", replacement: "Write `minimizationClaim` instead." },
        RemovedKey { pointer: "/privacyExpectation/subject_bindings", replacement: "Write `subjectBindings` instead." },
    ],
};

/// The most cases one fixture holds.
pub const MAXIMUM_CASES: usize = 256;

/// Read one synthetic fixture file. Local bundles may use focused suites;
/// production and evidence-grade bundles require every case category. `file` is the name the diagnostics carry.
/// `declared_unresolved` says whether the requirement's initial source
/// declares an unresolved outcome a case may replay.
///
/// The value returned is the document without its envelope, for the offline
/// runner.
pub fn read_fixture(
    file: &str,
    bytes: &[u8],
    declared_unresolved: bool,
    assurance_profile: AssuranceProfile,
) -> Result<Value, Report> {
    let mut hook = BundleExpressions;
    let document = Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::one(&EVIDENCE_FIXTURE_FORMAT))?;
    let mut value = document.to_json_value();
    let case_ids = if value.get("coequalAcceptanceDefinition") == Some(&Value::Bool(true)) {
        document
            .decode::<shape::CoequalFixture>()?
            .cases
            .iter()
            .map(|case| case.id.as_str().to_owned())
            .collect::<Vec<_>>()
    } else {
        document
            .decode::<shape::ReferenceFixture>()?
            .cases
            .iter()
            .map(|case| case.id.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    let case_pointers = (0..case_ids.len())
        .map(|index| format!("/cases/{index}/id"))
        .collect::<Vec<_>>();
    let case_ids = case_ids
        .iter()
        .zip(&case_pointers)
        .map(|(id, pointer)| AuthoredId::at_value(id, pointer))
        .collect::<Vec<_>>();
    let mut diagnostics =
        local_id_collision_diagnostics(&document, "evidence.fixture.case-id-collision", &case_ids);
    if let Err(diagnostic) =
        check_coverage(&document, &value, declared_unresolved, assurance_profile)
    {
        diagnostics.push(*diagnostic);
    }
    if !diagnostics.is_empty() {
        return Err(document.report_with(diagnostics));
    }
    if let Some(body) = value.as_object_mut() {
        body.remove("apiVersion");
        body.remove("kind");
    }
    Ok(value)
}

/// Typed control-key shells for the two existing evaluator forms. Synthetic
/// source/response, selector, fact and expected-value trees use ForeignValue:
/// their keys and nulls belong to the reviewed source or output contract.
/// The runtime evaluates the original document after this single shape check.
pub(crate) mod shape {
    #![allow(
        dead_code,
        reason = "fixture shells validate the existing authored keys; the evaluator retains original nodes"
    )]
    use registry_platform_yaml::{ForeignValue, Identified, LocalId, UniqueIdList};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ReferenceFixture {
        #[cfg_attr(feature = "schema", schemars(extend("const" = true)))]
        pub synthetic_only: bool,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
        pub cases: UniqueIdList<ReferenceCase>,
        pub common: Option<ReferenceCommon>,
        pub privacy_expectation: Option<ReferencePrivacy>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct CoequalFixture {
        #[cfg_attr(feature = "schema", schemars(extend("const" = true)))]
        pub synthetic_only: bool,
        #[cfg_attr(feature = "schema", schemars(extend("const" = true)))]
        pub coequal_acceptance_definition: bool,
        #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
        pub cases: UniqueIdList<CoequalCase>,
        pub common: Option<CoequalCommon>,
        pub privacy_expectation: Option<CoequalPrivacy>,
        pub provider_contract: Option<ForeignValue>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ReferenceCommon {
        pub observed_at: Option<String>,
        pub purpose: Option<String>,
        pub audience: Option<String>,
        pub extract: Option<String>,
        pub selectors: Option<ForeignValue>,
        pub verified_token_claims: Option<ForeignValue>,
        pub derivation_selector_inputs: Option<ForeignValue>,
        pub expected_request_parts: Option<ForeignValue>,
        pub expected_transport: Option<ForeignValue>,
        pub expected_fetch_request_parts: Option<ForeignValue>,
        pub expected_fetch_transport: Option<ForeignValue>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct CoequalCommon {
        pub observed_at: Option<String>,
        pub legal_local_date: Option<String>,
        pub purpose: Option<String>,
        pub audience: Option<String>,
        pub selector: Option<ForeignValue>,
        pub selectors: Option<ForeignValue>,
        pub subjects: Option<ForeignValue>,
        pub verified_token_claims: Option<ForeignValue>,
        pub derivation_selector_inputs: Option<ForeignValue>,
        pub expected_request_parts: Option<ForeignValue>,
        pub expected_transport: Option<ForeignValue>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ReferenceCase {
        pub id: LocalId,
        pub purpose: Option<String>,
        pub audience: Option<String>,
        pub observed_at: Option<String>,
        pub source_failure: Option<String>,
        pub bundle_mutation: Option<String>,
        pub statement_mutation: Option<String>,
        pub request_mutation: Option<String>,
        pub derivation_mutation: Option<String>,
        pub derivation_parameter_mutation: Option<ForeignValue>,
        #[cfg_attr(feature="schema", schemars(extend("const" = true)))]
        pub declared_unresolved: Option<bool>,
        pub response: Option<ForeignValue>,
        pub responses: Option<ForeignValue>,
        pub selectors: Option<ForeignValue>,
        pub selector_overrides: Option<ForeignValue>,
        pub expected: Option<ReferenceExpected>,
    }
    impl Identified for ReferenceCase {
        fn id(&self) -> &str {
            self.id.as_str()
        }
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct CoequalCase {
        pub id: LocalId,
        pub purpose: Option<String>,
        pub audience: Option<String>,
        pub observed_at: Option<String>,
        pub legal_local_date: Option<String>,
        pub expected: Option<String>,
        pub expected_lookup: Option<String>,
        pub expected_public_problem: Option<String>,
        pub source_failure: Option<String>,
        pub companion_bundle: Option<String>,
        pub derivation_runs: Option<bool>,
        pub signed_success: Option<bool>,
        pub expected_subject_roles: Option<Vec<String>>,
        pub source: Option<ForeignValue>,
        pub sources: Option<ForeignValue>,
        pub selectors: Option<ForeignValue>,
        pub selector_overrides: Option<ForeignValue>,
        pub subjects: Option<ForeignValue>,
        pub verified_token_claims: Option<ForeignValue>,
        pub derivation_selector_inputs: Option<ForeignValue>,
        pub injected_derivation: Option<ForeignValue>,
        pub expected_value: Option<ForeignValue>,
        pub expected_values: Option<ForeignValue>,
    }
    impl Identified for CoequalCase {
        fn id(&self) -> &str {
            self.id.as_str()
        }
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ReferenceExpected {
        pub lookup: Option<String>,
        pub public_problem: Option<String>,
        pub error: Option<String>,
        pub bundle: Option<String>,
        pub output_gate: Option<String>,
        pub rejected_before: Option<String>,
        pub raw_references_disclosed: Option<bool>,
        pub signed: Option<bool>,
        pub derivation_runs: Option<bool>,
        // The evaluator counts references in one list concept, whose limit is 64 items.
        pub entity_reference_count: Option<registry_platform_yaml::BoundedU64<0, 64>>,
        pub source_request_count: Option<registry_platform_yaml::BoundedU64<0, 2>>,
        pub facts: Option<ForeignValue>,
        pub value: Option<ForeignValue>,
        pub values: Option<ForeignValue>,
        pub expected_transport: Option<ForeignValue>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct ReferencePrivacy {
        pub evidence_contains: Option<Vec<String>>,
        pub evidence_excludes: Option<Vec<String>>,
        pub diagnostics_exclude: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub(crate) struct CoequalPrivacy {
        pub evidence_contains: Option<Vec<String>>,
        pub evidence_excludes: Option<Vec<String>>,
        pub diagnostics_exclude: Option<Vec<String>>,
        pub member_inputs: Option<String>,
        pub minimization_claim: Option<String>,
        pub subject_bindings: Option<String>,
    }
}

type Refusal = Box<registry_platform_yaml::Diagnostic>;

fn check_coverage(
    document: &Document,
    root: &Value,
    declared_unresolved: bool,
    assurance_profile: AssuranceProfile,
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
    if root.get("syntheticOnly") != Some(&Value::Bool(true)) {
        return Err(refuse(
            "evidence.fixture.not-synthetic",
            "/syntheticOnly",
            "a fixture declares syntheticOnly: true",
            "Declare `syntheticOnly: true` and use invented values only.",
        ));
    }
    let cases = root["cases"]
        .as_array()
        .expect("the typed shell has a case list");
    if cases.is_empty() || cases.len() > MAXIMUM_CASES {
        return Err(refuse(
            "evidence.fixture.invalid-case-count",
            "/cases",
            "a fixture holds from 1 to 256 cases",
            "Declare at least one case, and split a longer fixture between requirements.",
        ));
    }
    let mut categories = Categories::default();
    for (index, case) in cases.iter().enumerate() {
        let id = case["id"]
            .as_str()
            .expect("the typed shell has a local case id");
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
    if assurance_profile != AssuranceProfile::Local && !categories.complete() {
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
        let report = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            declared_unresolved,
            AssuranceProfile::EvidenceGrade,
        )
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
        let text = format!("{HEADER}syntheticOnly: true\ncases:\n{}", complete_cases());
        let value = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            false,
            AssuranceProfile::EvidenceGrade,
        )
        .expect("a complete fixture");
        assert_eq!(value.get("apiVersion"), None);
        assert_eq!(value.get("kind"), None);
        assert_eq!(value["cases"].as_array().map(Vec::len), Some(8));
    }

    #[test]
    fn focused_coverage_is_local_only() {
        let text = format!("{HEADER}syntheticOnly: true\ncases:\n  - {{id: positive}}\n");
        let value = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            false,
            AssuranceProfile::Local,
        )
        .expect("local focused fixture");
        assert_eq!(value["cases"].as_array().map(Vec::len), Some(1));
        for profile in [
            AssuranceProfile::Production,
            AssuranceProfile::EvidenceGrade,
        ] {
            let report = read_fixture("fixtures/cases.yaml", text.as_bytes(), false, profile)
                .expect_err("strict profiles require complete coverage");
            assert_eq!(report.files_checked(), Some(1));
            assert_eq!(
                report.diagnostics()[0].code,
                "evidence.fixture.incomplete-coverage"
            );
        }
        let complete = format!("{HEADER}syntheticOnly: true\ncases:\n{}", complete_cases());
        read_fixture(
            "fixtures/cases.yaml",
            complete.as_bytes(),
            false,
            AssuranceProfile::Local,
        )
        .expect("complete local fixtures remain valid");
    }

    #[test]
    fn focused_local_coverage_preserves_structural_and_private_refusals() {
        for (body, code) in [
            (
                "syntheticOnly: false\ncases: [{id: positive}]\n".to_owned(),
                "evidence.fixture.not-synthetic",
            ),
            (
                "syntheticOnly: true\ncases: []\n".to_owned(),
                "evidence.fixture.invalid-case-count",
            ),
            (
                "syntheticOnly: true\ncases: [{id: positive}, {id: positive}]\n".to_owned(),
                "config.duplicate-id",
            ),
            (
                format!("syntheticOnly: true\ncases: [{{id: {CANARY}}}]\n"),
                "config.invalid-value",
            ),
            (
                "syntheticOnly: true\ncases: [{id: unresolved, declaredUnresolved: true}]\n"
                    .to_owned(),
                "evidence.fixture.unresolved-not-declared",
            ),
        ] {
            let report = read_fixture(
                "fixtures/cases.yaml",
                format!("{HEADER}{body}").as_bytes(),
                false,
                AssuranceProfile::Local,
            )
            .expect_err("local coverage changes no structural boundary");
            assert_eq!(report.files_checked(), Some(1));
            assert_eq!(report.diagnostics()[0].code, code);
            assert!(!report.render_human().contains(CANARY));
        }
    }

    #[test]
    fn a_retired_header_without_the_envelope_is_refused_and_named() {
        let text = format!(
            "fixture: registry.evidence.reference.{CANARY}/v1\nsyntheticOnly: true\ncases:\n{}",
            complete_cases()
        );
        let report = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            false,
            AssuranceProfile::EvidenceGrade,
        )
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
                format!("{HEADER}fixture: registry.evidence.reference.{CANARY}/v1\nsyntheticOnly: true\ncases:\n{cases}"),
                false,
                "config.removed-key",
                "/fixture",
                3,
            ),
            (
                "not synthetic",
                format!("{HEADER}syntheticOnly: false\ncases:\n{cases}"),
                false,
                "evidence.fixture.not-synthetic",
                "/syntheticOnly",
                3,
            ),
            (
                "cases not a list",
                format!("{HEADER}syntheticOnly: true\ncases: {CANARY}\n"),
                false,
                "config.invalid-type",
                "/cases",
                4,
            ),
            (
                "repeated case id",
                format!("{HEADER}syntheticOnly: true\ncases:\n{cases}  - {{id: positive}}\n"),
                false,
                "config.duplicate-id",
                "/cases/8/id",
                13,
            ),
            (
                "unresolved without a source declaration",
                format!("{HEADER}syntheticOnly: true\ncases:\n{without_ambiguous}  - {{id: unresolved, declaredUnresolved: true}}\n"),
                false,
                "evidence.fixture.unresolved-not-declared",
                "/cases/7/declaredUnresolved",
                12,
            ),
            (
                "unresolved marker not true",
                format!("{HEADER}syntheticOnly: true\ncases:\n{without_ambiguous}  - {{id: unresolved, declaredUnresolved: false}}\n"),
                true,
                "evidence.fixture.invalid-unresolved-marker",
                "/cases/7/declaredUnresolved",
                12,
            ),
            (
                "incomplete coverage",
                format!("{HEADER}syntheticOnly: true\ncases:\n{without_ambiguous}"),
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
                "{HEADER}syntheticOnly: true\ncases:\n{cases}  - {{id: unresolved, declaredUnresolved: {marker}}}\n"
            )
        };
        read_fixture(
            "fixtures/cases.yaml",
            fixture("true").as_bytes(),
            true,
            AssuranceProfile::EvidenceGrade,
        )
        .expect("the declared unresolved case covers no-match and ambiguity");

        // The marker counts only when the requirement declares the collapse,
        // and only as `true`; either other way the hidden categories stay
        // uncovered.
        for (marker, declared, code) in [
            ("true", false, "evidence.fixture.unresolved-not-declared"),
            ("false", true, "evidence.fixture.invalid-unresolved-marker"),
        ] {
            let report = read_fixture(
                "fixtures/cases.yaml",
                fixture(marker).as_bytes(),
                declared,
                AssuranceProfile::EvidenceGrade,
            )
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
    #[test]
    fn both_fixture_forms_close_controls_and_preserve_foreign_payloads() {
        for (marker, payload) in [
            ("", "response"),
            ("coequalAcceptanceDefinition: true\n", "source"),
        ] {
            let text = format!("{HEADER}syntheticOnly: true\n{marker}cases:\n  - id: positive\n    {payload}: {{external_key: null, nested: {{unfamiliar: [1, true]}}}}\n");
            let value = read_fixture(
                "fixtures/cases.yaml",
                text.as_bytes(),
                false,
                AssuranceProfile::Local,
            )
            .unwrap();
            assert_eq!(value["cases"][0][payload]["external_key"], Value::Null);
            for (text, path) in [
                (
                    format!("{text}unknownControl: {CANARY}\n"),
                    "/unknownControl",
                ),
                (
                    format!("{text}common: {{unknownControl: {CANARY}}}\n"),
                    "/common/unknownControl",
                ),
                (
                    text.replace(
                        "id: positive",
                        &format!("id: positive\n    unknownControl: {CANARY}"),
                    ),
                    "/cases/0/unknownControl",
                ),
            ] {
                let report = read_fixture(
                    "fixtures/cases.yaml",
                    text.as_bytes(),
                    false,
                    AssuranceProfile::Local,
                )
                .unwrap_err();
                assert!(report
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == "config.unknown-key"
                        && diagnostic.path == path));
                assert!(!report.render_human().contains(CANARY));
            }
        }
    }

    #[test]
    fn duplicate_fixture_ids_keep_both_shared_source_locations() {
        let text =
            format!("{HEADER}syntheticOnly: true\ncases:\n  - id: positive\n  - id: positive\n");
        let report = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            false,
            AssuranceProfile::Local,
        )
        .unwrap_err();
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.duplicate-id");
        assert_eq!(diagnostic.path, "/cases/1/id");
        assert_eq!(diagnostic.source.as_ref().unwrap().line, Some(6));
        assert_eq!(diagnostic.related[0].path, "/cases/0/id");
        assert_eq!(diagnostic.related[0].line, Some(5));
    }

    #[test]
    fn separator_colliding_fixture_ids_keep_both_shared_source_locations() {
        for (marker, first_line, second_line) in
            [("", 5, 6), ("coequalAcceptanceDefinition: true\n", 6, 7)]
        {
            let text = format!(
                "{HEADER}syntheticOnly: true\n{marker}cases:\n  - id: source-failure\n  - id: source_failure\n"
            );
            let report = read_fixture(
                "fixtures/cases.yaml",
                text.as_bytes(),
                false,
                AssuranceProfile::Local,
            )
            .expect_err("separator-lookalike case IDs must be refused");
            assert_eq!(report.files_checked(), Some(1));
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "evidence.fixture.case-id-collision")
                .expect("the fixture collision has its own diagnostic");
            assert_eq!(diagnostic.path, "/cases/1/id");
            assert_eq!(diagnostic.related[0].path, "/cases/0/id");
            let source = diagnostic.source.as_ref().expect("second ID is positioned");
            assert_eq!(source.file, "fixtures/cases.yaml");
            assert_eq!((source.line, source.column), (Some(second_line), Some(9)));
            assert_eq!(diagnostic.related[0].file, "fixtures/cases.yaml");
            assert_eq!(
                (diagnostic.related[0].line, diagnostic.related[0].column),
                (Some(first_line), Some(9))
            );
            assert!(diagnostic.message.contains("`source-failure`"));
            assert!(diagnostic.message.contains("`source_failure`"));
        }
    }

    #[test]
    fn separator_collisions_retain_independent_fixture_coverage_refusals() {
        let text = format!(
            "{HEADER}syntheticOnly: false\ncases:\n  - id: source-failure\n  - id: source_failure\n"
        );
        let report = read_fixture(
            "fixtures/cases.yaml",
            text.as_bytes(),
            false,
            AssuranceProfile::Local,
        )
        .expect_err("the collision and non-synthetic fixture must both be refused");

        assert_eq!(report.files_checked(), Some(1));
        for (code, path) in [
            ("evidence.fixture.case-id-collision", "/cases/1/id"),
            ("evidence.fixture.not-synthetic", "/syntheticOnly"),
        ] {
            assert!(
                report
                    .diagnostics()
                    .iter()
                    .any(|diagnostic| diagnostic.code == code && diagnostic.path == path),
                "missing {code} at {path}: {report:#?}"
            );
        }
    }

    #[test]
    fn retired_fixture_controls_name_the_replacement_without_touching_payload_keys() {
        let base = format!("{HEADER}syntheticOnly: true\ncoequalAcceptanceDefinition: true\ncases:\n  - id: positive\n    source: {{synthetic_only: null, expected_lookup: kept}}\n");
        read_fixture(
            "fixtures/cases.yaml",
            base.as_bytes(),
            false,
            AssuranceProfile::Local,
        )
        .unwrap();
        for (text, path, replacement) in [
            (
                format!("{base}synthetic_only: true\n"),
                "/synthetic_only",
                "syntheticOnly",
            ),
            (
                format!("{base}common: {{observed_at: '2026-08-02T00:00:00Z'}}\n"),
                "/common/observed_at",
                "observedAt",
            ),
            (
                base.replace("id: positive", "id: positive\n    expected_lookup: match"),
                "/cases/0/expected_lookup",
                "expectedLookup",
            ),
        ] {
            let report = read_fixture(
                "fixtures/cases.yaml",
                text.as_bytes(),
                false,
                AssuranceProfile::Local,
            )
            .unwrap_err();
            let diagnostic = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.path == path)
                .unwrap();
            assert_eq!(diagnostic.code, "config.removed-key");
            assert!(diagnostic.suggested_action.contains(replacement));
        }
    }
}
