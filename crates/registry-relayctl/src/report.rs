// SPDX-License-Identifier: Apache-2.0
//! Plain-text rendering of the shared Relay V2 tooling report.
//!
//! The report is the sole source of every line below. This module reads the
//! values the shared library already returned; it never recompiles a project,
//! reinterprets a compiler outcome, reclassifies a change, or adds a value the
//! JSON rendering does not already carry. Every enumeration label is the label
//! serde writes into that JSON, so the two renderings share one vocabulary.

use serde::ser::Error as _;
use serde::Serialize;

use crate::shared::{
    ChangeImpact, ChangeImpactReport, Diagnostic, DiagnosticSeverity, FixturePlanReport,
    InspectedObject, PackageManifest, ToolingDetails, ToolingReport, ToolingStatus,
};

/// Ordinary detail indent, and the width of one nesting level.
const INDENT: &str = "  ";
/// Widest severity label, so a mixed list keeps one message column.
const SEVERITY_WIDTH: usize = 7;
/// Widest change-impact label, so a mixed list keeps one description column.
const IMPACT_WIDTH: usize = 13;
/// Separator between the columns of one rendered line.
const GAP: &str = "  ";
/// Widest a data-derived column may be padded. One long value must not push
/// every other line past a terminal width and wrap the whole list.
const ALIGN_LIMIT: usize = 40;

/// Render one report as the plain lead sentence, its indented detail, and the
/// diagnostics the report carries. Every diagnostic is rendered, in a stable
/// order, so this rendering stays lossless against the JSON one.
pub(crate) fn render_human(report: &ToolingReport) -> Result<String, serde_json::Error> {
    let refused = report.status == ToolingStatus::Refused;
    let mut lines = vec![lead(report, refused)];
    detail_lines(&report.details, &mut lines)?;
    if !report.diagnostics.is_empty() {
        lines.push(String::new());
        diagnostic_lines(&report.diagnostics, &mut lines)?;
        lines.push(String::new());
        lines.push(diagnostic_summary(&report.diagnostics));
    }
    lines.push(String::new());
    // Every value a report carries can originate in adopter input: a schema
    // identifier read from SQLite, a key path, or a diagnostic message that
    // interpolates an authored name. A report line is built from spaces and
    // report text only, so escaping each finished line here neutralizes every
    // such value at one boundary, whatever produced it. Escaped text is plain
    // ASCII, so a value already escaped for column alignment passes through
    // unchanged.
    let escaped: Vec<String> = lines.iter().map(|line| escape_report_text(line)).collect();
    Ok(escaped.join("\n"))
}

fn lead(report: &ToolingReport, refused: bool) -> String {
    match &report.details {
        ToolingDetails::Initialized { files } => {
            if refused {
                "Project initialization refused.".to_owned()
            } else {
                format!(
                    "Initialized an authoring project. {} written.",
                    counted(files.len(), "file")
                )
            }
        }
        ToolingDetails::SchemaInspection { objects, .. } => {
            if refused {
                "Schema inspection refused.".to_owned()
            } else {
                format!(
                    "Inspected the SQLite structure. {}.",
                    counted(objects.len(), "object")
                )
            }
        }
        ToolingDetails::Check { production, .. } => {
            let profile = if *production {
                "Production check"
            } else {
                "Authoring check"
            };
            let outcome = if refused { "refused" } else { "passed" };
            format!("{profile} {outcome}.")
        }
        ToolingDetails::Generate { artifacts, .. } => {
            if refused {
                "Artifact generation refused.".to_owned()
            } else {
                format!("Generated {}.", counted(artifacts.len(), "artifact"))
            }
        }
        ToolingDetails::Test { report, .. } => match (refused, report) {
            (true, _) => "Fixture run refused.".to_owned(),
            (false, Some(plan)) => {
                format!("Fixture run passed. {}.", counted(plan.steps.len(), "step"))
            }
            (false, None) => "Fixture run passed.".to_owned(),
        },
        ToolingDetails::Diff { report } => match (refused, report) {
            (true, _) => "Change classification refused.".to_owned(),
            (false, Some(impact)) if impact.changes.is_empty() => "No contract changes.".to_owned(),
            (false, Some(impact)) => format!(
                "{} classified.",
                counted(impact.changes.len(), "contract change")
            ),
            (false, None) => "Change classification reported nothing.".to_owned(),
        },
        ToolingDetails::Package { manifest } => match (refused, manifest) {
            (true, _) => "Packaging refused.".to_owned(),
            (false, Some(manifest)) => format!(
                "Sealed a deployment package. {}, {}.",
                counted(manifest.artifacts.len(), "artifact"),
                counted(manifest.files.len(), "file")
            ),
            (false, None) => "Sealed a deployment package.".to_owned(),
        },
    }
}

fn detail_lines(
    details: &ToolingDetails,
    lines: &mut Vec<String>,
) -> Result<(), serde_json::Error> {
    match details {
        ToolingDetails::Initialized { files } => {
            for file in files {
                lines.push(format!("{INDENT}{file}"));
            }
        }
        ToolingDetails::SchemaInspection {
            fingerprint,
            objects,
            starter_file,
            statistical_starter_file,
        } => {
            let mut pairs = vec![("fingerprint", fingerprint.clone())];
            if let Some(file) = starter_file {
                pairs.push(("starter", file.clone()));
            }
            if let Some(file) = statistical_starter_file {
                pairs.push(("statistical starter", file.clone()));
            }
            push_pairs(lines, INDENT, &pairs);
            if !objects.is_empty() {
                lines.push(String::new());
            }
            for object in objects {
                push_object(lines, object)?;
            }
        }
        ToolingDetails::Check {
            contract_revision,
            configuration_key_paths,
            ..
        } => {
            let mut pairs = Vec::new();
            if let Some(revision) = contract_revision {
                pairs.push(("contract revision", revision.clone()));
            }
            if let Some(paths) = configuration_key_paths {
                pairs.push(("registry key paths", paths.registry.len().to_string()));
                pairs.push(("runtime key paths", paths.runtime.len().to_string()));
            }
            push_pairs(lines, INDENT, &pairs);
        }
        ToolingDetails::Generate {
            contract_revision,
            artifacts,
        } => {
            let mut pairs = Vec::new();
            if let Some(revision) = contract_revision {
                pairs.push(("contract revision", revision.clone()));
            }
            push_pairs(lines, INDENT, &pairs);
            if !artifacts.is_empty() {
                lines.push(String::new());
            }
            let width = align_width(artifacts.iter().map(|artifact| artifact.id.len()));
            for artifact in artifacts {
                let id = &artifact.id;
                lines.push(format!("{INDENT}{id:<width$}{GAP}{}", artifact.path));
            }
        }
        ToolingDetails::Test {
            contract_revision,
            report,
        } => {
            let mut pairs = Vec::new();
            if let Some(revision) = contract_revision {
                pairs.push(("contract revision", revision.clone()));
            }
            if let Some(plan) = report {
                pairs.push(("registry", plan.registry_identifier.clone()));
                if let Some(fixture) = &plan.selected_fixture {
                    pairs.push(("fixture", fixture.clone()));
                }
            }
            push_pairs(lines, INDENT, &pairs);
            if let Some(plan) = report {
                push_steps(lines, plan);
            }
        }
        ToolingDetails::Diff { report } => {
            if let Some(impact) = report {
                push_pairs(
                    lines,
                    INDENT,
                    &[
                        ("previous revision", impact.previous_revision.clone()),
                        ("current revision", impact.current_revision.clone()),
                    ],
                );
                push_changes(lines, impact)?;
            }
        }
        ToolingDetails::Package { manifest } => {
            if let Some(manifest) = manifest {
                push_manifest(lines, manifest);
            }
        }
    }
    Ok(())
}

/// Nothing restricts what an adopter-supplied name may contain. SQLite places no restriction on an
/// identifier or a declared type, and an authored key path or column name reaches a diagnostic
/// message unchanged, so any of them can carry a line break, a terminal escape sequence, or a
/// Unicode bidirectional override that would forge a report line or redraw the text around it. This
/// replaces each such character with a visible, all-ASCII escape, so the value stays on the one line
/// it was given and cannot issue an instruction to the terminal or the reader. Ordinary printable
/// Unicode, including non-English identifiers, passes through unchanged, and text that is already
/// escaped is unchanged by a second pass.
fn escape_report_text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if is_unsafe_for_a_report_line(character) {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// C0 and C1 control characters (including newline, carriage return, tab, and escape) and DEL are
/// unsafe for any terminal. The Unicode bidirectional formatting and override characters are unsafe
/// for the same reason `rustc` denies them in a source literal: one of them can redraw the characters
/// that follow it, so a name carrying one can read as different text than the bytes it is.
fn is_unsafe_for_a_report_line(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{200e}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn push_object(lines: &mut Vec<String>, object: &InspectedObject) -> Result<(), serde_json::Error> {
    let kind = wire_label(&object.kind)?;
    let mut header = vec![kind, escape_report_text(&object.name)];
    if object.table_name != object.name {
        header.push(format!("on {}", escape_report_text(&object.table_name)));
    }
    lines.push(format!("{INDENT}{}", header.join(GAP)));

    let columns: Vec<(String, String)> = object
        .columns
        .iter()
        .map(|column| {
            (
                escape_report_text(&column.name),
                escape_report_text(&column.declared_type),
            )
        })
        .collect();
    let name_width = align_width(columns.iter().map(|(name, _)| name.len()));
    let type_width = align_width(columns.iter().map(|(_, declared)| declared.len()));
    for (column, (name, declared)) in object.columns.iter().zip(&columns) {
        let nullable = if column.nullable {
            "nullable"
        } else {
            "not null"
        };
        let key = if column.primary_key {
            format!("{GAP}primary key")
        } else {
            String::new()
        };
        lines.push(format!(
            "{INDENT}{INDENT}{name:<name_width$}{GAP}{declared:<type_width$}{GAP}{nullable}{key}"
        ));
    }
    Ok(())
}

fn push_steps(lines: &mut Vec<String>, plan: &FixturePlanReport) {
    if plan.steps.is_empty() {
        return;
    }
    lines.push(String::new());
    for step in &plan.steps {
        let outcome = match step.passed {
            Some(true) => "pass",
            Some(false) => "fail",
            None => "-",
        };
        let operation = step.operation_identifier.as_deref().unwrap_or("-");
        let actual = step
            .actual_status
            .map_or_else(|| "-".to_owned(), |status| status.to_string());
        let code = step.actual_code.as_deref().unwrap_or_default();
        let columns = [
            format!("{outcome:<4}"),
            step.id.clone(),
            operation.to_owned(),
            format!("expected {}", step.expected_status),
            format!("actual {actual}"),
            code.to_owned(),
        ];
        lines.push(format!("{INDENT}{}", join_columns(&columns)));
    }
}

fn push_changes(
    lines: &mut Vec<String>,
    report: &ChangeImpactReport,
) -> Result<(), serde_json::Error> {
    if report.changes.is_empty() {
        return Ok(());
    }
    lines.push(String::new());
    for change in &report.changes {
        let impact = wire_label(&change.impact)?;
        let class = wire_label(&change.class)?;
        lines.push(format!(
            "{INDENT}{impact:<IMPACT_WIDTH$}{GAP}{class}{GAP}{}",
            change.location
        ));
        lines.push(format!(
            "{}{}",
            " ".repeat(INDENT.len() + IMPACT_WIDTH + GAP.len()),
            change.description
        ));
    }
    lines.push(String::new());
    let count = |wanted: ChangeImpact| {
        report
            .changes
            .iter()
            .filter(|change| change.impact == wanted)
            .count()
    };
    lines.push(format!(
        "{} breaking, {} widening, {} narrowing, {} informational.",
        count(ChangeImpact::Breaking),
        count(ChangeImpact::Widening),
        count(ChangeImpact::Narrowing),
        count(ChangeImpact::Informational)
    ));
    Ok(())
}

fn push_manifest(lines: &mut Vec<String>, manifest: &PackageManifest) {
    push_pairs(
        lines,
        INDENT,
        &[
            ("package version", manifest.package_version.clone()),
            ("package revision", manifest.package_revision.clone()),
            ("contract revision", manifest.contract_revision.clone()),
            (
                "artifact bindings",
                manifest.operation_artifact_bindings.len().to_string(),
            ),
        ],
    );
    if manifest.source_schema_fingerprints.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(format!("{INDENT}source schema fingerprints"));
    let pairs = manifest
        .source_schema_fingerprints
        .iter()
        .map(|(source, fingerprint)| (source.as_str(), fingerprint.clone()))
        .collect::<Vec<_>>();
    push_pairs(lines, &format!("{INDENT}{INDENT}"), &pairs);
}

fn diagnostic_lines(
    diagnostics: &[Diagnostic],
    lines: &mut Vec<String>,
) -> Result<(), serde_json::Error> {
    for severity in [DiagnosticSeverity::Error, DiagnosticSeverity::Warning] {
        for item in diagnostics.iter().filter(|item| item.severity == severity) {
            let label = wire_label(&item.severity)?;
            lines.push(format!(
                "{INDENT}{label:<SEVERITY_WIDTH$}{GAP}{}{GAP}{}",
                item.code, item.location
            ));
            lines.push(format!(
                "{}{}",
                " ".repeat(INDENT.len() + SEVERITY_WIDTH + GAP.len()),
                item.message
            ));
        }
    }
    Ok(())
}

fn diagnostic_summary(diagnostics: &[Diagnostic]) -> String {
    let errors = diagnostics
        .iter()
        .filter(|item| item.severity == DiagnosticSeverity::Error)
        .count();
    format!(
        "{}, {}.",
        counted(errors, "error"),
        counted(diagnostics.len() - errors, "warning")
    )
}

/// Render aligned `label  value` detail lines under one lead sentence.
fn push_pairs(lines: &mut Vec<String>, indent: &str, pairs: &[(&str, String)]) {
    let width = pairs
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or_default();
    for (label, value) in pairs {
        lines.push(format!("{indent}{label:<width$}{GAP}{value}"));
    }
}

/// The padding width for a column of adopter-supplied values: wide enough for
/// the ordinary ones, never wide enough for one outlier to wrap every line.
fn align_width(widths: impl Iterator<Item = usize>) -> usize {
    widths.max().unwrap_or_default().min(ALIGN_LIMIT)
}

fn join_columns(columns: &[String]) -> String {
    columns
        .iter()
        .filter(|column| !column.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(GAP)
}

fn counted(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

/// The label serde already assigns to a report enumeration. Reading it here
/// keeps the human sentence and the JSON document in one vocabulary instead of
/// restating the compiler's terms in adopter tooling.
fn wire_label<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(label) => Ok(label),
        _ => Err(serde_json::Error::custom(
            "a report label did not serialize as one string",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(document: &str) -> ToolingReport {
        serde_json::from_str(document).expect("the report fixture parses")
    }

    fn rendered(document: &str) -> String {
        render_human(&report(document)).expect("the report renders")
    }

    const INITIALIZED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "initialized",
        "files": ["registry.yaml", "runtime.yaml"]
      }
    }"#;

    const INITIALIZATION_REFUSED: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "project.destination_not_empty",
          "location": ".",
          "message": "initialization requires a new or empty project directory"
        }
      ],
      "details": {"kind": "initialized", "files": []}
    }"#;

    const INSPECTION: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "index",
            "name": "source_records_key",
            "tableName": "source_records",
            "columns": []
          },
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {"name": "record_identifier", "declaredType": "TEXT", "nullable": false, "primaryKey": true},
              {"name": "region_code", "declaredType": "TEXT", "nullable": true, "primaryKey": false}
            ]
          }
        ],
        "starter_file": "schema-starter.yaml",
        "statistical_starter_file": "statistical-dataset-starter.yaml"
      }
    }"#;

    const CHECK_REFUSED: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "warning",
          "code": "contract.review_pending",
          "location": "resources[0]",
          "message": "a suggested review entry is still unreviewed"
        },
        {
          "severity": "error",
          "code": "runtime.issuer_missing",
          "location": "runtime.yaml.authentication.issuer",
          "message": "a Registry with protected operations requires one configured issuer"
        },
        {
          "severity": "error",
          "code": "source.schema_observation_missing",
          "location": "sources.registry",
          "message": "production compilation requires the observed source schema"
        }
      ],
      "details": {
        "kind": "check",
        "contract_revision": null,
        "production": true,
        "configuration_key_paths": null
      }
    }"#;

    const CHECK_PASSED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "check",
        "contract_revision": "sha256:bbbb",
        "production": false,
        "configuration_key_paths": {
          "registry": ["apiVersion", "sources.*.path"],
          "runtime": ["apiVersion"]
        }
      }
    }"#;

    const GENERATED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "generate",
        "contract_revision": "sha256:cccc",
        "artifacts": [
          {"id": "capability-inventory", "path": "artifacts/capabilities.json", "sha256": "sha256:dddd"},
          {"id": "identification-report", "path": "identification-report.md", "sha256": "sha256:eeee"}
        ]
      }
    }"#;

    const FIXTURE_RUN_REFUSED: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "fixture.status_mismatch",
          "location": "steps[1]",
          "message": "the fixture step returned another status"
        }
      ],
      "details": {
        "kind": "test",
        "contract_revision": "sha256:ffff",
        "report": {
          "registryIdentifier": "urn:example:registry:records",
          "selectedFixture": null,
          "steps": [
            {
              "id": "first-page",
              "operationIdentifier": "record.list",
              "expectedStatus": 200,
              "actualStatus": 200,
              "actualCode": null,
              "passed": true
            },
            {
              "id": "refused-page",
              "operationIdentifier": "record.list",
              "expectedStatus": 200,
              "actualStatus": 403,
              "actualCode": "relay.forbidden",
              "passed": false
            }
          ],
          "diagnostics": [
            {
              "code": "fixture.status_mismatch",
              "location": "steps[1]",
              "message": "the fixture step returned another status"
            }
          ]
        }
      }
    }"#;

    const DIFF_CHANGED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "diff",
        "report": {
          "previousRevision": "sha256:1111",
          "currentRevision": "sha256:2222",
          "changes": [
            {
              "class": "pagination-expanded",
              "impact": "widening",
              "location": "resources[0].operations.list.pagination",
              "description": "the maximum page size increased"
            },
            {
              "class": "filter-removed",
              "impact": "breaking",
              "location": "resources[0].operations.list.filters",
              "description": "a request filter was removed"
            }
          ]
        }
      }
    }"#;

    const DIFF_UNCHANGED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "diff",
        "report": {
          "previousRevision": "sha256:1111",
          "currentRevision": "sha256:1111",
          "changes": []
        }
      }
    }"#;

    const PACKAGED: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "package",
        "manifest": {
          "packageVersion": "relay.registrystack.org/package/v1alpha3",
          "packageRevision": "sha256:3333",
          "contractRevision": "sha256:4444",
          "sourceSchemaFingerprints": {"records": "sha256:5555"},
          "sourceSchemas": {
            "records": {
              "source": "records",
              "fingerprint": "sha256:5555",
              "views": [
                {
                  "name": "relay_records",
                  "columns": [
                    {"name": "record_identifier", "declaredType": "TEXT", "nullable": true, "primaryKey": false}
                  ]
                }
              ]
            }
          },
          "artifacts": [
            {
              "id": "capability-inventory",
              "path": "generated/artifacts/capabilities.json",
              "mediaType": "application/json",
              "visibility": "public",
              "operationIdentifier": null,
              "accessBinding": null,
              "sha256": "sha256:6666"
            }
          ],
          "operationArtifactBindings": [
            {
              "operationIdentifier": "record.list",
              "accessProfileIdentifier": "public-view",
              "vocabularyPath": "artifacts/record--list.vocabulary.jsonld",
              "contextPath": "artifacts/record--list.context.jsonld",
              "accessProfileSchemaPath": "artifacts/record--list.schema.json",
              "accessProfileShaclPath": "artifacts/record--list.shacl.ttl",
              "classificationPath": "artifacts/record--list.classifications.json",
              "processingPath": "artifacts/record--list.processing.json"
            }
          ],
          "files": [
            {
              "path": "generated/artifacts/capabilities.json",
              "size": 512,
              "sha256": "sha256:6666",
              "mediaType": "application/json",
              "visibility": "public",
              "generated": true
            }
          ]
        }
      }
    }"#;

    const PACKAGE_REFUSED: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "classification.unreviewed",
          "location": "resources[0].properties.recordValue.classification",
          "message": "production compilation requires reviewed classification"
        }
      ],
      "details": {"kind": "package", "manifest": null}
    }"#;

    /// Every fixture above is one report the shared library can return, so the
    /// rendering tests never describe a shape the JSON contract does not have.
    const EVERY_FIXTURE: [&str; 11] = [
        INITIALIZED,
        INITIALIZATION_REFUSED,
        INSPECTION,
        CHECK_REFUSED,
        CHECK_PASSED,
        GENERATED,
        FIXTURE_RUN_REFUSED,
        DIFF_CHANGED,
        DIFF_UNCHANGED,
        PACKAGED,
        PACKAGE_REFUSED,
    ];

    #[test]
    fn every_rendering_is_plain_ascii_text_and_ends_with_one_newline() {
        for document in EVERY_FIXTURE {
            let output = rendered(document);
            assert!(output.is_ascii(), "rendering left ASCII: {output}");
            assert!(!output.contains('\u{1b}'), "rendering used an escape code");
            assert!(output.ends_with('\n'), "rendering lacks a trailing newline");
            assert!(
                !output.ends_with("\n\n"),
                "rendering ends with a blank line"
            );
            assert!(!output.starts_with('{'), "rendering opened a JSON document");
            for line in output.lines() {
                assert_eq!(line.trim_end(), line, "line has trailing space: {line:?}");
            }
        }
    }

    #[test]
    fn initialization_lists_every_written_file() {
        assert_eq!(
            rendered(INITIALIZED),
            "Initialized an authoring project. 2 files written.\n  registry.yaml\n  runtime.yaml\n"
        );
    }

    #[test]
    fn initialization_refusal_states_the_refusal_and_counts_last() {
        assert_eq!(
            rendered(INITIALIZATION_REFUSED),
            concat!(
                "Project initialization refused.\n",
                "\n",
                "  error    project.destination_not_empty  .\n",
                "           initialization requires a new or empty project directory\n",
                "\n",
                "1 error, 0 warnings.\n",
            )
        );
    }

    #[test]
    fn inspection_renders_objects_and_their_columns() {
        assert_eq!(
            rendered(INSPECTION),
            concat!(
                "Inspected the SQLite structure. 2 objects.\n",
                "  fingerprint          sha256:aaaa\n",
                "  starter              schema-starter.yaml\n",
                "  statistical starter  statistical-dataset-starter.yaml\n",
                "\n",
                "  index  source_records_key  on source_records\n",
                "  table  source_records\n",
                "    record_identifier  TEXT  not null  primary key\n",
                "    region_code        TEXT  nullable\n",
            )
        );
    }

    #[test]
    fn production_refusal_orders_errors_before_warnings_without_grouping() {
        assert_eq!(
            rendered(CHECK_REFUSED),
            concat!(
                "Production check refused.\n",
                "\n",
                "  error    runtime.issuer_missing  runtime.yaml.authentication.issuer\n",
                "           a Registry with protected operations requires one configured issuer\n",
                "  error    source.schema_observation_missing  sources.registry\n",
                "           production compilation requires the observed source schema\n",
                "  warning  contract.review_pending  resources[0]\n",
                "           a suggested review entry is still unreviewed\n",
                "\n",
                "2 errors, 1 warning.\n",
            )
        );
    }

    #[test]
    fn a_passing_check_summarizes_the_configuration_key_paths() {
        assert_eq!(
            rendered(CHECK_PASSED),
            concat!(
                "Authoring check passed.\n",
                "  contract revision   sha256:bbbb\n",
                "  registry key paths  2\n",
                "  runtime key paths   1\n",
            )
        );
    }

    #[test]
    fn generation_lists_every_artifact() {
        assert_eq!(
            rendered(GENERATED),
            concat!(
                "Generated 2 artifacts.\n",
                "  contract revision  sha256:cccc\n",
                "\n",
                "  capability-inventory   artifacts/capabilities.json\n",
                "  identification-report  identification-report.md\n",
            )
        );
    }

    const GENERATED_WITH_A_LONG_IDENTIFIER: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "generate",
        "contract_revision": null,
        "artifacts": [
          {"id": "capability-inventory", "path": "artifacts/capabilities.json", "sha256": "sha256:dddd"},
          {
            "id": "an-identifier-far-longer-than-the-column-alignment-limit-allows",
            "path": "artifacts/long.json",
            "sha256": "sha256:eeee"
          }
        ]
      }
    }"#;

    #[test]
    fn one_long_identifier_does_not_widen_every_other_line() {
        let output = rendered(GENERATED_WITH_A_LONG_IDENTIFIER);
        let widest = output
            .lines()
            .map(|line| line.chars().count())
            .max()
            .expect("the rendering has lines");

        assert_eq!(
            output,
            concat!(
                "Generated 2 artifacts.\n",
                "\n",
                "  capability-inventory                      artifacts/capabilities.json\n",
                "  an-identifier-far-longer-than-the-column-alignment-limit-allows  \
artifacts/long.json\n",
            )
        );
        // The short line is padded to the limit, not to the outlier's width.
        assert!(
            widest < 2 + 63 + 2 + "artifacts/capabilities.json".len(),
            "a single long identifier widened the whole list: {widest}"
        );
    }

    #[test]
    fn a_fixture_run_renders_every_step_and_its_refusal() {
        assert_eq!(
            rendered(FIXTURE_RUN_REFUSED),
            concat!(
                "Fixture run refused.\n",
                "  contract revision  sha256:ffff\n",
                "  registry           urn:example:registry:records\n",
                "\n",
                "  pass  first-page  record.list  expected 200  actual 200\n",
                "  fail  refused-page  record.list  expected 200  actual 403  relay.forbidden\n",
                "\n",
                "  error    fixture.status_mismatch  steps[1]\n",
                "           the fixture step returned another status\n",
                "\n",
                "1 error, 0 warnings.\n",
            )
        );
    }

    #[test]
    fn a_diff_renders_every_change_and_counts_each_impact() {
        assert_eq!(
            rendered(DIFF_CHANGED),
            concat!(
                "2 contract changes classified.\n",
                "  previous revision  sha256:1111\n",
                "  current revision   sha256:2222\n",
                "\n",
                "  widening       pagination-expanded  resources[0].operations.list.pagination\n",
                "                 the maximum page size increased\n",
                "  breaking       filter-removed  resources[0].operations.list.filters\n",
                "                 a request filter was removed\n",
                "\n",
                "1 breaking, 1 widening, 0 narrowing, 0 informational.\n",
            )
        );
    }

    #[test]
    fn an_unchanged_diff_states_that_and_stops() {
        assert_eq!(
            rendered(DIFF_UNCHANGED),
            concat!(
                "No contract changes.\n",
                "  previous revision  sha256:1111\n",
                "  current revision   sha256:1111\n",
            )
        );
    }

    #[test]
    fn a_sealed_package_renders_its_revisions_and_source_fingerprints() {
        assert_eq!(
            rendered(PACKAGED),
            concat!(
                "Sealed a deployment package. 1 artifact, 1 file.\n",
                "  package version    relay.registrystack.org/package/v1alpha3\n",
                "  package revision   sha256:3333\n",
                "  contract revision  sha256:4444\n",
                "  artifact bindings  1\n",
                "\n",
                "  source schema fingerprints\n",
                "    records  sha256:5555\n",
            )
        );
    }

    #[test]
    fn a_refused_package_renders_the_refusal_without_a_manifest() {
        assert_eq!(
            rendered(PACKAGE_REFUSED),
            concat!(
                "Packaging refused.\n",
                "\n",
                "  error    classification.unreviewed  resources[0].properties.recordValue.classification\n",
                "           production compilation requires reviewed classification\n",
                "\n",
                "1 error, 0 warnings.\n",
            )
        );
    }

    #[test]
    fn every_diagnostic_the_report_carries_is_rendered_once() {
        let repeated = r#"{
          "status": "refused",
          "diagnostics": [
            {
              "severity": "error",
              "code": "classification.unreviewed",
              "location": "resources[0].sourceColumnClassifications",
              "message": "production compilation requires reviewed classification"
            },
            {
              "severity": "error",
              "code": "classification.unreviewed",
              "location": "resources[0].sourceColumnClassifications",
              "message": "production compilation requires reviewed classification"
            }
          ],
          "details": {
            "kind": "check",
            "contract_revision": null,
            "production": true,
            "configuration_key_paths": null
          }
        }"#;

        let output = rendered(repeated);

        assert_eq!(
            output
                .lines()
                .filter(|line| line.contains("classification.unreviewed"))
                .count(),
            2
        );
        assert!(output.ends_with("2 errors, 0 warnings.\n"));
    }

    // SQLite accepts a quoted identifier containing any byte a `TEXT` value can hold, including
    // newlines, terminal escape sequences, and Unicode bidirectional overrides. Nothing upstream of
    // this renderer restricts a schema name to a safe character set, so a hostile schema must not be
    // able to forge a report line, emit a terminal escape sequence, or visually reorder the text
    // around it. These fixtures use the same JSON shape as `INSPECTION`, with one schema-derived
    // string replaced by a value a hostile schema could carry.

    const INSPECTION_HOSTILE_COLUMN_NAME: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {
                "name": "region_code\n\u001b[31mFORGED: 0 errors, 0 warnings.\u001b[0m",
                "declaredType": "TEXT",
                "nullable": true,
                "primaryKey": false
              }
            ]
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    const INSPECTION_CONTROL_COLUMN_NAME: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {
                "name": "region_code_safe_control_value",
                "declaredType": "TEXT",
                "nullable": true,
                "primaryKey": false
              }
            ]
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    #[test]
    fn a_hostile_column_name_cannot_forge_a_report_line() {
        let hostile = rendered(INSPECTION_HOSTILE_COLUMN_NAME);
        let control = rendered(INSPECTION_CONTROL_COLUMN_NAME);

        assert!(
            !hostile.contains('\u{1b}'),
            "a raw escape byte reached the rendering: {hostile:?}"
        );
        assert_eq!(
            hostile.lines().count(),
            control.lines().count(),
            "the embedded newline changed the number of report lines: {hostile:?}"
        );
        assert!(
            !hostile.lines().any(|line| line.starts_with("FORGED")),
            "the forged text opened its own report line: {hostile:?}"
        );
    }

    const INSPECTION_HOSTILE_OBJECT_NAMES: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "index",
            "name": "source_records_key\n\u001b[31mFORGED: 0 errors, 0 warnings.\u001b[0m",
            "tableName": "source_records\n\u001b[32mFORGED-TABLE\u001b[0m",
            "columns": []
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    const INSPECTION_CONTROL_OBJECT_NAMES: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "index",
            "name": "source_records_key_safe_control_value",
            "tableName": "source_records_safe_control_value",
            "columns": []
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    #[test]
    fn a_hostile_object_or_table_name_cannot_forge_a_report_line() {
        let hostile = rendered(INSPECTION_HOSTILE_OBJECT_NAMES);
        let control = rendered(INSPECTION_CONTROL_OBJECT_NAMES);

        assert!(
            !hostile.contains('\u{1b}'),
            "a raw escape byte reached the rendering: {hostile:?}"
        );
        assert_eq!(
            hostile.lines().count(),
            control.lines().count(),
            "an embedded newline changed the number of report lines: {hostile:?}"
        );
        assert!(
            !hostile
                .lines()
                .any(|line| line.starts_with("FORGED") || line.starts_with("FORGED-TABLE")),
            "the forged text opened its own report line: {hostile:?}"
        );
    }

    const INSPECTION_HOSTILE_DECLARED_TYPE: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {
                "name": "region_code",
                "declaredType": "TEXT\n\u001b[31mFORGED: 0 errors, 0 warnings.\u001b[0m",
                "nullable": true,
                "primaryKey": false
              }
            ]
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    const INSPECTION_CONTROL_DECLARED_TYPE: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {
                "name": "region_code",
                "declaredType": "TEXT_safe_control_value",
                "nullable": true,
                "primaryKey": false
              }
            ]
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    #[test]
    fn a_hostile_declared_type_cannot_forge_a_report_line() {
        let hostile = rendered(INSPECTION_HOSTILE_DECLARED_TYPE);
        let control = rendered(INSPECTION_CONTROL_DECLARED_TYPE);

        assert!(
            !hostile.contains('\u{1b}'),
            "a raw escape byte reached the rendering: {hostile:?}"
        );
        assert_eq!(
            hostile.lines().count(),
            control.lines().count(),
            "the embedded newline changed the number of report lines: {hostile:?}"
        );
        assert!(
            !hostile.lines().any(|line| line.starts_with("FORGED")),
            "the forged text opened its own report line: {hostile:?}"
        );
    }

    // A raw string literal cannot hold U+202E directly: rustc denies an invisible
    // text-direction codepoint appearing literally in source. `\u{202e}` keeps the
    // codepoint out of the source text while still producing it in the parsed JSON.
    const INSPECTION_BIDI_OVERRIDE_COLUMN_NAME: &str = "{
      \"status\": \"success\",
      \"diagnostics\": [],
      \"details\": {
        \"kind\": \"schema-inspection\",
        \"fingerprint\": \"sha256:aaaa\",
        \"objects\": [
          {
            \"kind\": \"table\",
            \"name\": \"source_records\",
            \"tableName\": \"source_records\",
            \"columns\": [
              {
                \"name\": \"region\u{202e}code_public\",
                \"declaredType\": \"TEXT\",
                \"nullable\": true,
                \"primaryKey\": false
              }
            ]
          }
        ],
        \"starter_file\": null,
        \"statistical_starter_file\": null
      }
    }";

    /// U+202E (RIGHT-TO-LEFT OVERRIDE) tells a terminal or editor to draw the characters after it in
    /// reverse, so a column named `region\u{202e}code_public` can draw as something else entirely.
    /// Left in the rendering, it would keep reordering everything printed after it on the same line.
    #[test]
    fn a_bidi_override_in_a_column_name_is_neutralized() {
        let output = rendered(INSPECTION_BIDI_OVERRIDE_COLUMN_NAME);
        assert!(
            !output.contains('\u{202e}'),
            "a raw bidirectional override character reached the rendering: {output:?}"
        );
    }

    const INSPECTION_NON_ASCII_COLUMN_NAMES: &str = r#"{
      "status": "success",
      "diagnostics": [],
      "details": {
        "kind": "schema-inspection",
        "fingerprint": "sha256:aaaa",
        "objects": [
          {
            "kind": "table",
            "name": "source_records",
            "tableName": "source_records",
            "columns": [
              {"name": "région_code", "declaredType": "TEXT", "nullable": true, "primaryKey": false},
              {"name": "注册", "declaredType": "TEXT", "nullable": true, "primaryKey": false}
            ]
          }
        ],
        "starter_file": null,
        "statistical_starter_file": null
      }
    }"#;

    /// Legitimate schemas use non-English identifiers. Escaping is for bytes that are dangerous to a
    /// terminal or a reader, not for ordinary printable Unicode outside ASCII, so a name like these
    /// must reach the rendering unchanged and still readable.
    #[test]
    fn non_ascii_column_names_render_intact() {
        let output = rendered(INSPECTION_NON_ASCII_COLUMN_NAMES);
        assert!(
            output.contains("région_code"),
            "a non-ASCII Latin column name was altered: {output:?}"
        );
        assert!(
            output.contains("注册"),
            "a non-ASCII CJK column name was altered: {output:?}"
        );
    }

    // A diagnostic carries an authored key path in `location` and an authored source-column name
    // inside `message`. Neither is restricted to a safe character set, and both are written into a
    // report line, so the same forging a hostile schema name allows is reachable through an
    // authoring document. These fixtures pair a hostile diagnostic with an identically shaped safe
    // one, so each assertion compares against a real control rendering.

    const DIAGNOSTIC_HOSTILE_MESSAGE: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "classification.column_incomplete",
          "location": "resources[0].classificationDefaults",
          "message": "an accounted source column has no complete classification for source column 'id\n\u001b[31mFORGED: 0 errors, 0 warnings.\u001b[0m'"
        }
      ],
      "details": {
        "kind": "check",
        "contract_revision": null,
        "production": true,
        "configuration_key_paths": null
      }
    }"#;

    const DIAGNOSTIC_HOSTILE_LOCATION: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "classification.column_incomplete",
          "location": "resources[0].sourceColumnClassifications.id\n\u001b[31mFORGED: 0 errors, 0 warnings.\u001b[0m",
          "message": "an accounted source column has no complete classification"
        }
      ],
      "details": {
        "kind": "check",
        "contract_revision": null,
        "production": true,
        "configuration_key_paths": null
      }
    }"#;

    const DIAGNOSTIC_CONTROL: &str = r#"{
      "status": "refused",
      "diagnostics": [
        {
          "severity": "error",
          "code": "classification.column_incomplete",
          "location": "resources[0].classificationDefaults",
          "message": "an accounted source column has no complete classification"
        }
      ],
      "details": {
        "kind": "check",
        "contract_revision": null,
        "production": true,
        "configuration_key_paths": null
      }
    }"#;

    #[test]
    fn a_hostile_diagnostic_message_cannot_forge_a_report_line() {
        let hostile = rendered(DIAGNOSTIC_HOSTILE_MESSAGE);
        let control = rendered(DIAGNOSTIC_CONTROL);

        assert!(
            !hostile.contains('\u{1b}'),
            "a raw escape byte reached the rendering: {hostile:?}"
        );
        assert_eq!(
            hostile.lines().count(),
            control.lines().count(),
            "the embedded newline changed the number of report lines: {hostile:?}"
        );
        assert!(
            !hostile
                .lines()
                .any(|line| line.trim_start().starts_with("FORGED")),
            "the forged text opened its own report line: {hostile:?}"
        );
    }

    #[test]
    fn a_hostile_diagnostic_location_cannot_forge_a_report_line() {
        let hostile = rendered(DIAGNOSTIC_HOSTILE_LOCATION);
        let control = rendered(DIAGNOSTIC_CONTROL);

        assert!(
            !hostile.contains('\u{1b}'),
            "a raw escape byte reached the rendering: {hostile:?}"
        );
        assert_eq!(
            hostile.lines().count(),
            control.lines().count(),
            "the embedded newline changed the number of report lines: {hostile:?}"
        );
        assert!(
            !hostile
                .lines()
                .any(|line| line.trim_start().starts_with("FORGED")),
            "the forged text opened its own report line: {hostile:?}"
        );
    }
}
