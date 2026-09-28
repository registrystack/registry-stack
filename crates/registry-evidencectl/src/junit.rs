//! JUnit XML rendering for fixture runs, for CI systems that collect test
//! reports rather than parse the JSON report.
//!
//! The document is a projection of the same run report the JSON output
//! carries: one `check` suite for the runtime's bundle check, then one suite
//! per fixture file with one test case per case the runtime's structured trace
//! named. A fixture whose trace named no case is reported as a single test
//! case named after the fixture. Nothing here decides a verdict: every pass or
//! failure is the one the runtime reported.

use std::io::Write as _;

use serde_json::Value as JsonValue;

use crate::fixtures::{FixtureReport, RunReport};

/// One case the runtime's structured trace named, and the fixed failure
/// message that ended it, when one did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaseResult {
    pub(crate) id: String,
    pub(crate) failure: Option<String>,
}

/// The cases a structured trace names, in evaluation order.
pub(crate) fn case_results(trace: Option<&JsonValue>) -> Vec<CaseResult> {
    trace
        .and_then(|trace| trace.get("cases"))
        .and_then(JsonValue::as_array)
        .map(|cases| {
            cases
                .iter()
                .filter_map(|case| {
                    Some(CaseResult {
                        id: case.get("id")?.as_str()?.to_owned(),
                        failure: case
                            .get("failure")
                            .and_then(JsonValue::as_str)
                            .map(str::to_owned),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Write the JUnit document for one run to standard output.
pub(crate) fn print(command: &str, report: &RunReport) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(render(command, report).as_bytes())?;
    stdout.flush()
}

pub(crate) fn render(command: &str, report: &RunReport) -> String {
    let mut suites = Vec::new();
    let check_failure = (!report.check.passed).then(|| Failure {
        message: "evidence check refused the bundle".to_owned(),
        detail: report.check.stderr.clone(),
    });
    suites.push(Suite {
        name: "check".to_owned(),
        cases: vec![Case {
            name: "evidence check".to_owned(),
            failure: check_failure,
        }],
    });
    for fixture in &report.fixtures {
        suites.push(fixture_suite(fixture));
    }
    // A run whose every step passed can still fail because it evaluated no
    // case. The document says so, so that it never reads greener than the
    // exit code.
    if !report.passed && suites.iter().all(|suite| suite.failures() == 0) {
        suites.push(Suite {
            name: "run".to_owned(),
            cases: vec![Case {
                name: "evaluated cases".to_owned(),
                failure: Some(Failure {
                    message: "no case was evaluated, so this run proves nothing".to_owned(),
                    detail: Some(
                        "Declare at least one case in every fixture the project references."
                            .to_owned(),
                    ),
                }),
            }],
        });
    }

    let tests: usize = suites.iter().map(|suite| suite.cases.len()).sum();
    let failures: usize = suites.iter().map(Suite::failures).sum();
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"{}\" tests=\"{tests}\" failures=\"{failures}\" errors=\"0\">\n",
        escape(&format!("evidencectl {command}"))
    ));
    for suite in &suites {
        xml.push_str(&format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"0\">\n",
            escape(&suite.name),
            suite.cases.len(),
            suite.failures()
        ));
        for case in &suite.cases {
            let open = format!(
                "    <testcase classname=\"{}\" name=\"{}\"",
                escape(&suite.name),
                escape(&case.name)
            );
            match &case.failure {
                None => xml.push_str(&format!("{open}/>\n")),
                Some(failure) => {
                    xml.push_str(&format!("{open}>\n"));
                    match failure
                        .detail
                        .as_deref()
                        .filter(|detail| !detail.is_empty())
                    {
                        None => xml.push_str(&format!(
                            "      <failure message=\"{}\"/>\n",
                            escape(&failure.message)
                        )),
                        Some(detail) => xml.push_str(&format!(
                            "      <failure message=\"{}\">{}</failure>\n",
                            escape(&failure.message),
                            escape(detail)
                        )),
                    }
                    xml.push_str("    </testcase>\n");
                }
            }
        }
        xml.push_str("  </testsuite>\n");
    }
    xml.push_str("</testsuites>\n");
    xml
}

struct Suite {
    name: String,
    cases: Vec<Case>,
}

impl Suite {
    fn failures(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.failure.is_some())
            .count()
    }
}

struct Case {
    name: String,
    failure: Option<Failure>,
}

struct Failure {
    message: String,
    detail: Option<String>,
}

fn fixture_suite(fixture: &FixtureReport) -> Suite {
    let failing_id = fixture
        .failing_case
        .as_ref()
        .map(|failing| failing.id.as_str());
    let mut cases: Vec<Case> = fixture
        .cases
        .iter()
        .map(|case| {
            let named_failing = failing_id == Some(case.id.as_str());
            let failure = if named_failing {
                let failing = fixture.failing_case.as_ref().expect("named failing case");
                Some(Failure {
                    message: failing.cause.clone(),
                    detail: fixture.stderr.clone(),
                })
            } else {
                case.failure.clone().map(|message| Failure {
                    message,
                    detail: None,
                })
            };
            Case {
                name: case.id.clone(),
                failure,
            }
        })
        .collect();
    // A failed fixture whose failure no listed case carries still fails in
    // the report, so a reader of the XML alone never sees a failed run as
    // green.
    let carried = cases.iter().any(|case| case.failure.is_some());
    if cases.is_empty() || (!fixture.passed && !carried) {
        let message = fixture
            .failing_case
            .as_ref()
            .map(|failing| failing.cause.clone())
            .unwrap_or_else(|| "the fixture run failed".to_owned());
        cases.push(Case {
            name: fixture.path.clone(),
            failure: (!fixture.passed).then(|| Failure {
                message,
                detail: fixture.stderr.clone(),
            }),
        });
    }
    Suite {
        name: fixture.path.clone(),
        cases,
    }
}

/// Escape text for an XML attribute or element, dropping the control
/// characters XML 1.0 cannot carry at all.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(character),
            control if control < ' ' => {}
            other => escaped.push(other),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_quotes_and_forbidden_controls() {
        assert_eq!(
            escape("a<b>&\"c\"'d'\u{1}\n"),
            "a&lt;b&gt;&amp;&quot;c&quot;&apos;d&apos;\n"
        );
    }

    #[test]
    fn case_results_read_the_trace_cases_in_order() {
        let trace = serde_json::json!({
            "passed": false,
            "cases": [
                {"id": "adult", "stages": []},
                {"id": "minor", "stages": [], "failure": "the result did not match"}
            ]
        });
        assert_eq!(
            case_results(Some(&trace)),
            vec![
                CaseResult {
                    id: "adult".to_owned(),
                    failure: None
                },
                CaseResult {
                    id: "minor".to_owned(),
                    failure: Some("the result did not match".to_owned())
                },
            ]
        );
        assert!(case_results(None).is_empty());
    }
}
