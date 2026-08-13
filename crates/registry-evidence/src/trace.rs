//! A per-stage record of one offline fixture evaluation, for `--explain`.
//!
//! The offline evaluation path reports a failure as one fixed operator message,
//! which says that a case failed but never why. Everything needed to answer why
//! is computed on the way to that message and then dropped: which case was
//! running, how far it got, what shape the source response had, and which
//! declared concept the output gate was checking. This module keeps those as a
//! plain value so the command can print them beside the unchanged message.
//!
//! The record is a diagnostic, never a decision. Nothing here influences an
//! outcome, an exit code, or an error message, and the renderer is the only
//! reader. It is deliberately value-free: keys, identifiers, declared forms and
//! counts describe the shape an author got wrong without reprinting the
//! synthetic document itself.

use serde::Serialize;

/// The closed public-facing class of one fixture result.
///
/// These are deliberately coarser than runtime errors. They are sufficient to
/// distinguish a unique result, an unresolved lookup, and the three public
/// availability classes without exposing the values or implementation detail
/// that produced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResultClass {
    Match,
    NoMatch,
    Ambiguous,
    EvidenceUnavailable,
    SourceUnavailable,
    ServiceUnavailable,
    BundleRefused,
    SelectorRefused,
}

/// A bounded classification of a governed result value, never the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueClass {
    BooleanFalse,
    BooleanTrue,
    Integer,
    String,
    Bucket,
    EntityReference,
    Structured,
    List,
}

/// Why the observed result reached its closed class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    UniqueMatch,
    NoMatch,
    Ambiguous,
    ExtractionRefused,
    DerivationInputRefused,
    SourceProtocolRefused,
    ScriptRefused,
    OutputRefused,
    BundleRefused,
    RequirementRefused,
    EvidenceConstructionRefused,
    SelectorRefused,
    SourceFailureFixture,
    CompanionBundleRefused,
}

/// A closed repair finding. Absence means the expected and observed result
/// classifications agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingCode {
    LookupOutcomeMismatch,
    PublicProblemMismatch,
    DerivationExpectationMismatch,
    SigningExpectationMismatch,
    ResultValueMismatch,
    ResultShapeMismatch,
    InvalidExpectation,
    UnexpectedToolOutcome,
}

/// A controlled-category identity expressed only as governed positions.
///
/// `concept_ordinal` is the concept's position in the requirement and
/// `value_ordinal` is the value's position in that concept's captured
/// codelist. Neither ordinal is derived from source or selector data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryClass {
    pub concept_ordinal: usize,
    pub value_ordinal: usize,
}

/// One expected or observed result with values reduced to a closed shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultClassification {
    pub class: ResultClass,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub value_classes: Vec<ValueClass>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub category_classes: Vec<CategoryClass>,
}

impl ResultClassification {
    pub fn new(class: ResultClass, mut value_classes: Vec<ValueClass>) -> Self {
        value_classes.sort_unstable();
        value_classes.dedup();
        Self {
            class,
            value_classes,
            category_classes: Vec::new(),
        }
    }

    pub fn with_category_classes(mut self, mut category_classes: Vec<CategoryClass>) -> Self {
        category_classes.sort_unstable();
        category_classes.dedup();
        self.category_classes = category_classes;
        self
    }
}

/// One step of the offline pipeline, named in generic pipeline vocabulary.
///
/// The names describe what the runtime does, never what an acceptance
/// definition means, so a new definition never adds a stage.
///
/// `Validate` is the runtime's own output gate over derived values. `Expect` is
/// the separate step where the fixture harness compares what the pipeline did
/// against what the case declared it would do. Keeping the two apart is the
/// point: a case fails at one or the other, and each sends an author to a
/// different file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Prepare,
    Acquire,
    Extract,
    Derive,
    Validate,
    Construct,
    Sign,
    Expect,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Acquire => "acquire",
            Self::Extract => "extract",
            Self::Derive => "derive",
            Self::Validate => "validate",
            Self::Construct => "construct",
            Self::Sign => "sign",
            Self::Expect => "expect",
        }
    }
}

/// How one stage ended.
///
/// `NoMatch`, `Ambiguous`, and `Unresolved` are separated from `Failed`
/// because none is a defect. `Unresolved` is deliberately neutral: an HTTP
/// source may have hidden whether its exact declared outcome began as no match
/// or ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StageStatus {
    Ok,
    NoMatch,
    Ambiguous,
    Unresolved,
    Failed,
}

impl StageStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NoMatch => "no-match",
            Self::Ambiguous => "ambiguous",
            Self::Unresolved => "unresolved",
            Self::Failed => "failed",
        }
    }
}

/// One stage, its outcome, and the value-free evidence for that outcome.
#[derive(Debug, Serialize)]
pub struct StageRecord {
    pub stage: Stage,
    pub status: StageStatus,
    /// The one-line summary rendered beside the status.
    pub note: String,
    /// Further lines rendered under the note, in the order they were recorded.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// One fixture case: its identifier, the stages it reached, and its verdict.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseTrace {
    pub id: String,
    pub stages: Vec<StageRecord>,
    /// The fixed operator message that ended the case, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    /// The case's authored result reduced to the closed diagnostic vocabulary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_result: Option<ResultClassification>,
    /// What the authoritative evaluator produced, reduced the same way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_result: Option<ResultClassification>,
    /// The value-free cause of the observed result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
    /// Closed repair findings. This list is bounded by the one comparison the
    /// fixture harness performs for a case.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub finding_codes: Vec<FindingCode>,
    /// Whether the case reached a verdict. Not part of the rendered value; it
    /// only decides which case a later failure belongs to.
    #[serde(skip)]
    settled: bool,
}

/// Every case of one fixture run, in evaluation order.
#[derive(Debug, Default, Serialize)]
pub struct FixtureTrace {
    pub cases: Vec<CaseTrace>,
    /// What the fixture that built this trace declared must never appear in it.
    ///
    /// Not part of the rendered value. It travels with the trace so that
    /// whoever renders it can check it without loading the fixture again, which
    /// is what lets a run that stopped on an error be checked as closely as a
    /// run that settled every case.
    #[serde(skip)]
    canaries: Vec<String>,
}

/// One fixture run rendered for a machine reader.
///
/// The JSON form of `--explain` writes this document and nothing else, so a
/// reader pipes stdout without stripping a trailing human summary line. The
/// verdict and the evaluated-case count that the text mode prints on that line
/// move inside the document instead, and the trace flattens in beside them so
/// `cases` is the same value the text renderer reads.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureReport<'a> {
    pub passed: bool,
    /// Absent when the run failed before it reached a count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluated_cases: Option<usize>,
    #[serde(flatten)]
    pub trace: &'a FixtureTrace,
}

/// The case a failure is attributed to when it happened outside every case.
const FIXTURE_SCOPE: &str = "(fixture)";

impl FixtureTrace {
    /// Declare what this trace must never contain.
    ///
    /// Declared as soon as the fixture is read, before any case runs, so the
    /// canaries are in place for every trace that can still be rendered.
    pub fn declare_canaries(&mut self, canaries: Vec<String>) {
        self.canaries = canaries;
    }

    /// What the fixture declared must never appear in this trace.
    pub fn canaries(&self) -> &[String] {
        &self.canaries
    }

    /// Open a case. Stages recorded from here on belong to it.
    pub fn begin_case(&mut self, id: &str) {
        self.cases.push(CaseTrace {
            id: id.to_owned(),
            stages: Vec::new(),
            failure: None,
            expected_result: None,
            observed_result: None,
            reason_code: None,
            finding_codes: Vec::new(),
            settled: false,
        });
    }

    /// Attach the closed expected-versus-observed comparison to the open case.
    pub fn diagnose(
        &mut self,
        expected: ResultClassification,
        observed: ResultClassification,
        reason: ReasonCode,
        finding: Option<FindingCode>,
    ) {
        let case = self.open_case();
        case.expected_result = Some(expected);
        case.observed_result = Some(observed);
        case.reason_code = Some(reason);
        case.finding_codes = finding.into_iter().collect();
    }

    /// Record a stage against the open case.
    pub fn record(&mut self, stage: Stage, status: StageStatus, note: impl Into<String>) {
        self.record_with(stage, status, note, Vec::new());
    }

    /// Record a stage and the further lines that explain it.
    pub fn record_with(
        &mut self,
        stage: Stage,
        status: StageStatus,
        note: impl Into<String>,
        details: Vec<String>,
    ) {
        self.open_case().stages.push(StageRecord {
            stage,
            status,
            note: note.into(),
            details,
        });
    }

    /// Settle the open case as passed, alongside the evaluated-case counter.
    pub fn pass_case(&mut self) {
        if let Some(case) = self.cases.last_mut() {
            case.settled = true;
        }
    }

    /// Attribute a fixed operator message to whichever case was still running.
    ///
    /// A failure raised after every case settled belongs to the fixture rather
    /// than to the case that happens to be last, so it gets its own entry.
    pub fn fail(&mut self, message: &str) {
        let case = match self.cases.last_mut() {
            Some(case) if !case.settled => case,
            _ => {
                self.begin_case(FIXTURE_SCOPE);
                self.cases.last_mut().expect("a case was just opened")
            }
        };
        case.failure = Some(message.to_owned());
        case.settled = true;
    }

    /// The case stages attach to, opening a scope entry if none is running.
    fn open_case(&mut self) -> &mut CaseTrace {
        if self.cases.last().is_none_or(|case| case.settled) {
            self.begin_case(FIXTURE_SCOPE);
        }
        self.cases.last_mut().expect("a case is open")
    }

    /// Render the trace for a person, one case per block, in causal order.
    pub fn render(&self) -> String {
        let mut rendered = String::new();
        for case in &self.cases {
            rendered.push_str(&format!("case: {}\n", case.id));
            for stage in &case.stages {
                rendered.push_str(&format!(
                    "  {:<10} {:<10} {}\n",
                    stage.stage.label(),
                    stage.status.label(),
                    stage.note
                ));
                for detail in &stage.details {
                    rendered.push_str(&format!("{:24}{detail}\n", ""));
                }
            }
            match &case.failure {
                Some(message) => rendered.push_str(&format!("  -> case failed: {message}\n")),
                None if case.settled => rendered.push_str("  -> case passed\n"),
                None => rendered.push_str("  -> case did not reach a verdict\n"),
            }
        }
        rendered
    }
}

/// Name the keys of a JSON object, so an author sees the shape a script saw.
///
/// Only member names are taken. A response or fact set is synthetic here, but
/// printing its members would still make this the one place in the offline path
/// that reprints a document, and the shape is what a mismatch is about.
pub fn object_keys(value: &serde_json::Value) -> Vec<String> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

/// Render a list of names as a compact, stable, quoted sequence.
pub fn name_list(names: &[String]) -> String {
    let quoted = names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>();
    format!("[{}]", quoted.join(", "))
}

/// Name the JSON type of a value, for comparison against a declared form.
pub fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing_case() -> FixtureTrace {
        let mut trace = FixtureTrace::default();
        trace.begin_case("positive");
        trace.record(
            Stage::Prepare,
            StageStatus::Ok,
            "selector roles [\"subject\"]",
        );
        trace.record(
            Stage::Acquire,
            StageStatus::Ok,
            "1 source response, keys [\"date_of_birth\", \"total\"]",
        );
        trace.record(
            Stage::Extract,
            StageStatus::Ok,
            "fact keys [\"date_of_birth\"]",
        );
        trace.record(Stage::Derive, StageStatus::Ok, "1 gated concept value");
        trace.record(
            Stage::Validate,
            StageStatus::Ok,
            "the output gate accepted 1 declared concept",
        );
        trace.record(Stage::Expect, StageStatus::Ok, "case expectations matched");
        trace.record(Stage::Sign, StageStatus::Ok, "signed and verified offline");
        trace.pass_case();
        trace
    }

    #[test]
    fn a_passing_case_renders_every_stage_it_reached_in_causal_order() {
        let rendered = passing_case().render();
        let stage_order = [
            "prepare", "acquire", "extract", "derive", "validate", "expect", "sign",
        ];
        let mut cursor = 0;
        for stage in stage_order {
            let found = rendered[cursor..]
                .find(stage)
                .unwrap_or_else(|| panic!("rendered trace is missing stage {stage}"));
            cursor += found;
        }
        assert!(rendered.starts_with("case: positive\n"));
        assert!(rendered.contains("1 gated concept value"));
        assert!(rendered.trim_end().ends_with("-> case passed"));
        assert!(!rendered.contains("case failed"));
    }

    #[test]
    fn an_unmatched_extraction_renders_the_response_keys_that_were_available() {
        let mut trace = FixtureTrace::default();
        trace.begin_case("missing-record");
        trace.record(Stage::Acquire, StageStatus::Ok, "1 source response");
        trace.record_with(
            Stage::Extract,
            StageStatus::NoMatch,
            "the extraction script reported no match",
            vec![format!(
                "response keys available {}",
                name_list(&object_keys(&serde_json::json!({
                    "pager": {},
                    "instances": [],
                    "headers": []
                })))
            )],
        );
        trace.fail("fixture lookup outcome did not match its contract");

        let rendered = trace.render();
        assert!(rendered.contains("extract    no-match"));
        assert!(
            rendered.contains("response keys available [\"headers\", \"instances\", \"pager\"]")
        );
        assert!(
            rendered.contains("-> case failed: fixture lookup outcome did not match its contract")
        );
    }

    #[test]
    fn a_rejected_output_value_renders_the_concept_and_the_check_that_rejected_it() {
        let mut trace = FixtureTrace::default();
        trace.begin_case("negative-wrong-derived-type");
        trace.record_with(
            Stage::Validate,
            StageStatus::Failed,
            "the output gate rejected 1 of 1 derived values",
            vec![format!(
                "concept \"urn:example:concept:flag\" declares form \"boolean\", \
                 derived value is {}",
                json_type(&serde_json::json!("true"))
            )],
        );
        trace.fail("injected derivation was not rejected");

        let rendered = trace.render();
        assert!(rendered.contains("validate   failed"));
        assert!(rendered.contains("concept \"urn:example:concept:flag\""));
        assert!(rendered.contains("declares form \"boolean\", derived value is string"));
        assert!(rendered.contains("-> case failed: injected derivation was not rejected"));
    }

    #[test]
    fn a_failure_after_every_case_settled_is_attributed_to_the_fixture_and_not_the_last_case() {
        let mut trace = passing_case();
        trace.fail("fixture privacy expectation was not met");

        let rendered = trace.render();
        assert!(rendered.contains("case: positive\n"));
        assert!(rendered.contains("  -> case passed\n"));
        assert!(rendered.contains("case: (fixture)\n"));
        assert!(rendered.contains("-> case failed: fixture privacy expectation was not met"));
    }

    #[test]
    fn detail_lines_align_under_the_note_column_they_explain() {
        let mut trace = FixtureTrace::default();
        trace.begin_case("aligned");
        trace.record_with(
            Stage::Extract,
            StageStatus::Failed,
            "note",
            vec!["detail".to_owned()],
        );
        trace.pass_case();

        let rendered = trace.render();
        let note_column = rendered
            .lines()
            .find(|line| line.contains("note"))
            .expect("the note line renders")
            .find("note")
            .expect("the note column is found");
        let detail_column = rendered
            .lines()
            .find(|line| line.contains("detail"))
            .expect("the detail line renders")
            .find("detail")
            .expect("the detail column is found");
        assert_eq!(note_column, detail_column);
    }

    #[test]
    fn a_passing_report_carries_the_verdict_and_the_count_the_summary_line_prints() {
        let trace = passing_case();
        let report = FixtureReport {
            passed: true,
            evaluated_cases: Some(13),
            trace: &trace,
        };
        let serialized = serde_json::to_value(&report).expect("the report is representable");

        assert_eq!(serialized["passed"], serde_json::json!(true));
        assert_eq!(serialized["evaluatedCases"], serde_json::json!(13));
        // Flattened, not nested: the trace's own `cases` array stays the top
        // level key a reader walks.
        assert_eq!(serialized["cases"][0]["id"], serde_json::json!("positive"));
    }

    #[test]
    fn a_result_diagnostic_is_closed_bounded_and_value_free() {
        let mut trace = FixtureTrace::default();
        trace.begin_case("wrong-governed-answer");
        trace.diagnose(
            ResultClassification::new(
                ResultClass::Match,
                vec![ValueClass::BooleanFalse, ValueClass::BooleanFalse],
            )
            .with_category_classes(vec![
                CategoryClass {
                    concept_ordinal: 1,
                    value_ordinal: 2,
                },
                CategoryClass {
                    concept_ordinal: 0,
                    value_ordinal: 1,
                },
                CategoryClass {
                    concept_ordinal: 1,
                    value_ordinal: 2,
                },
            ]),
            ResultClassification::new(ResultClass::Match, vec![ValueClass::BooleanTrue]),
            ReasonCode::UniqueMatch,
            Some(FindingCode::ResultValueMismatch),
        );
        trace.fail("fixture value did not match its contract");

        let serialized = serde_json::to_value(&trace).expect("trace serializes");
        let case = &serialized["cases"][0];
        assert_eq!(case["expectedResult"]["class"], serde_json::json!("match"));
        assert_eq!(
            case["expectedResult"]["valueClasses"],
            serde_json::json!(["boolean-false"])
        );
        assert_eq!(case["observedResult"]["class"], serde_json::json!("match"));
        assert_eq!(
            case["expectedResult"]["categoryClasses"],
            serde_json::json!([
                {"conceptOrdinal": 0, "valueOrdinal": 1},
                {"conceptOrdinal": 1, "valueOrdinal": 2}
            ])
        );
        assert_eq!(
            case["observedResult"]["valueClasses"],
            serde_json::json!(["boolean-true"])
        );
        assert_eq!(case["reasonCode"], serde_json::json!("unique-match"));
        assert_eq!(
            case["findingCodes"],
            serde_json::json!(["result-value-mismatch"])
        );
        let rendered = serialized.to_string();
        for prohibited in ["synthetic-person-001", "2000-01-01", "SELECT", "token-"] {
            assert!(!rendered.contains(prohibited));
        }
    }

    #[test]
    fn a_failing_report_omits_the_count_and_keeps_the_message_on_the_case_that_failed() {
        let mut trace = FixtureTrace::default();
        trace.begin_case("no-match");
        trace.record(Stage::Extract, StageStatus::NoMatch, "no match");
        trace.fail("fixture kernel failure did not match its public problem");
        let report = FixtureReport {
            passed: false,
            evaluated_cases: None,
            trace: &trace,
        };
        let serialized = serde_json::to_value(&report).expect("the report is representable");

        assert_eq!(serialized["passed"], serde_json::json!(false));
        assert_eq!(serialized.get("evaluatedCases"), None);
        assert_eq!(
            serialized["cases"][0]["failure"],
            serde_json::json!("fixture kernel failure did not match its public problem")
        );
    }

    #[test]
    fn the_serialized_form_carries_every_stage_so_a_machine_reader_stays_a_small_change() {
        let serialized =
            serde_json::to_value(passing_case()).expect("the trace is representable as JSON");
        assert_eq!(serialized["cases"][0]["id"], serde_json::json!("positive"));
        assert_eq!(
            serialized["cases"][0]["stages"][0]["stage"],
            serde_json::json!("prepare")
        );
        assert_eq!(
            serialized["cases"][0]["stages"][0]["status"],
            serde_json::json!("ok")
        );
    }
}
