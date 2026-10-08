// SPDX-License-Identifier: Apache-2.0
//! `bregctl check --file`: check one BReg tool file on its own.
//!
//! The file's `kind` names its format. The check reads the file through the
//! shared reader, applies the rules that hold without a session, a database,
//! a network or a secret, and reports what it found in the shared diagnostic
//! shape (CFG-DIAG-1, CFG-DIAG-2). It resolves no secret reference
//! (CFG-CHECK-1), writes nothing, and names no value the file holds
//! (CFG-SEC-3).

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use registry_breg::literal_text::{
    LiteralText, WRITE_THE_VALUE, WRITE_THE_VALUE_OR_A_SECRET_REFERENCE,
};
use registry_breg::{data, fixtures, migration_plan};
use registry_platform_yaml::{
    Diagnostic, Document, Expect, FormatSpec, NodeValue, Reader, Report, Severity, Source,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde::Serialize;

use crate::{
    data_lifecycle, dev, init_from_model, test_lifecycle, OutputFormat, DOMAIN_REFUSAL_EXIT,
    OPERATIONAL_FAILURE_EXIT,
};

/// What `bregctl check --file` was asked to check.
pub(crate) struct Request<'a> {
    pub file: &'a Path,
    /// The project a journeys document is checked against.
    pub project: Option<&'a Path>,
    pub deny_warnings: bool,
}

/// Why a check produced no findings.
pub(crate) enum Failure {
    /// The shared reader refused the document.
    Refused(Report),
    /// The check could not run; the diagnostic says what stopped it.
    Unavailable(Box<Diagnostic>),
}

impl Failure {
    pub(crate) fn unavailable(code: &str, message: &str, suggested_action: &str) -> Failure {
        Failure::Unavailable(Box::new(Diagnostic::error(
            code,
            "",
            message,
            suggested_action,
        )))
    }
}

impl From<Report> for Failure {
    fn from(report: Report) -> Failure {
        Failure::Refused(report)
    }
}

/// The context one format's check reads.
struct Input<'a> {
    document: &'a Document,
    bytes: &'a [u8],
    file: &'a Path,
    project: Option<&'a Path>,
}

type Check = fn(&Input<'_>) -> Result<Vec<Diagnostic>, Failure>;

/// Every format the command reads; the remedy a substitution expression in
/// it is refused with, when the file is read as written (CFG-SEC-2); and its
/// check. A file a command writes holds text it copied, which is never
/// substituted, so it has no remedy.
const CHECKS: [(FormatSpec<'static>, Option<&str>, Check); 15] = [
    (fixtures::JOURNEYS_FORMAT, Some(WRITE_THE_VALUE), journeys),
    (
        fixtures::SCHEMA_TEST_RECEIPT_FORMAT,
        None,
        schema_test_receipt,
    ),
    (
        test_lifecycle::CREDENTIALS_FORMAT,
        Some(WRITE_THE_VALUE_OR_A_SECRET_REFERENCE),
        |input| Ok(test_lifecycle::check_credentials(input.document)?),
    ),
    (data::IMPORT_CHECKPOINT_FORMAT, None, |input| {
        input.document.decode::<data::DataImportCheckpoint>()?;
        Ok(Vec::new())
    }),
    (data::EXPORT_CHECKPOINT_FORMAT, None, |input| {
        input.document.decode::<data::DataExportCheckpoint>()?;
        Ok(Vec::new())
    }),
    (data_lifecycle::IMPORT_STATE_FORMAT, None, |input| {
        Ok(data_lifecycle::check_import_state(input.document)?)
    }),
    (
        migration_plan::MIGRATION_DESCRIPTOR_FORMAT,
        Some(WRITE_THE_VALUE),
        |input| {
            Ok(migration_plan::check_migration_descriptor(
                input.document,
                descriptor_location(input.file).as_deref(),
            )?)
        },
    ),
    (
        migration_plan::MIGRATION_REHEARSAL_RECEIPT_FORMAT,
        None,
        |input| {
            input
                .document
                .decode::<migration_plan::MigrationRehearsalReceipt>()?;
            Ok(Vec::new())
        },
    ),
    (
        migration_plan::BACKUP_BINDING_FORMAT,
        Some(WRITE_THE_VALUE),
        |input| {
            Ok(migration_plan::check_backup_binding_document(
                input.document,
            )?)
        },
    ),
    (
        init_from_model::SELECTION_FORMAT,
        Some(WRITE_THE_VALUE),
        |input| init_from_model::check_selection(input.document),
    ),
    (
        dev::DEV_CLIENTS_FORMAT,
        Some(WRITE_THE_VALUE_OR_A_SECRET_REFERENCE),
        |input| Ok(dev::check_clients(input.document)?),
    ),
    (
        dev::examples::EXAMPLE_SCENARIOS_FORMAT,
        Some(WRITE_THE_VALUE),
        |input| Ok(dev::examples::check(input.document)?),
    ),
    (dev::DEV_STATE_FORMAT, None, |input| {
        Ok(dev::check_state(input.document)?)
    }),
    (dev::PREPARED_SOURCE_FORMAT, None, |input| {
        Ok(dev::check_prepared(input.document)?)
    }),
    (dev::SOURCE_TRANSITION_FORMAT, None, |input| {
        Ok(dev::check_transition(input.document)?)
    }),
];

/// The report `--format json` writes, success or not (CFG-DIAG-1).
#[derive(Serialize)]
struct FileCheckReport<'a> {
    ok: bool,
    command: &'static str,
    diagnostics: &'a [Diagnostic],
}

/// Check one file and write the report. Exits 0 when the file passes, 1 when
/// the check found an error (or a warning, with `--deny-warnings`), and 3
/// when the check could not run.
pub(crate) fn run(
    request: &Request<'_>,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let label = request.file.display().to_string();
    let outcome = check(request, &label);
    let (lead, report, exit) = match outcome {
        Ok(report) if report.has_errors() => (
            Some("bregctl check refused the file."),
            report,
            DOMAIN_REFUSAL_EXIT,
        ),
        Ok(report) if request.deny_warnings && report.warning_count() > 0 => (
            Some("bregctl check refused the file: --deny-warnings refuses a warning."),
            report,
            DOMAIN_REFUSAL_EXIT,
        ),
        Ok(report) => (None, report, 0),
        Err(Failure::Refused(report)) => (
            Some("bregctl check refused the file."),
            report,
            DOMAIN_REFUSAL_EXIT,
        ),
        Err(Failure::Unavailable(diagnostic)) => {
            let mut report = Report::new(vec![in_file(*diagnostic, &label)]);
            report.set_files_checked(1);
            (
                Some("bregctl check could not check the file."),
                report,
                OPERATIONAL_FAILURE_EXIT,
            )
        }
    };
    let written = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(
            &mut *stdout,
            &FileCheckReport {
                ok: exit == 0,
                command: "check",
                diagnostics: report.diagnostics(),
            },
        )
        .map_err(io::Error::other)
        .and_then(|()| writeln!(stdout))
    } else {
        // One sentence of the command's own, then the diagnostics and the
        // summary line unchanged.
        match lead {
            None => write!(stdout, "Check passed.\n{}", report.render_human()),
            Some(lead) => write!(stderr, "{lead}\n{}", report.render_human()),
        }
    };
    if written.is_err() {
        let _ = writeln!(stderr, "bregctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }
    ExitCode::from(exit)
}

fn check(request: &Request<'_>, label: &str) -> Result<Report, Failure> {
    let bytes = read(request.file, label)?;
    let formats: Vec<FormatSpec<'static>> = CHECKS.iter().map(|(format, ..)| *format).collect();
    // Whether the file may hold a substitution expression depends on its
    // format, which only its `kind` names, so the kind is looked up before
    // the read that refuses one. A file whose kind no format carries is read
    // with the refusal, so an expression in its envelope is named as one.
    let remedy = match written_kind(label, &bytes) {
        Some(kind) => CHECKS
            .iter()
            .find(|(format, ..)| format.kind == kind)
            .map_or(Some(WRITE_THE_VALUE), |(_, remedy, _)| *remedy),
        None => Some(WRITE_THE_VALUE),
    };
    let reader = Reader::new(label);
    let expect = Expect::new(&formats);
    let document = match remedy {
        Some(remedy) => reader
            .with_hook(&mut LiteralText { remedy })
            .read(&bytes, &expect)?,
        None => reader.read(&bytes, &expect)?,
    };
    let kind = document.envelope().kind.as_str();
    let Some((.., check)) = CHECKS.iter().find(|(format, ..)| format.kind == kind) else {
        unreachable!("the reader matched one of the formats it was given")
    };
    let findings = check(&Input {
        document: &document,
        bytes: &bytes,
        file: request.file,
        project: request.project,
    })?;
    let mut report = document.warnings();
    if request.project.is_some() && kind != fixtures::JOURNEYS_KIND {
        report.push(document.diagnostic_at_value(
            Severity::Warning,
            "breg.check.project-unused",
            "",
            "only a journeys document is checked against a project; this file was checked on its own",
            "Drop PROJECT when checking this file.",
        ));
    }
    for finding in findings {
        report.push(finding);
    }
    Ok(report)
}

/// The text the file writes as its root `kind`, when the shared reader can
/// read the file and the member is text.
fn written_kind(label: &str, bytes: &[u8]) -> Option<String> {
    let root = Reader::new(label).scan(bytes).ok()??;
    match &root.pointer("/kind")?.value {
        NodeValue::String(text) => Some(text.text.clone()),
        _ => None,
    }
}

/// Read the file, bounded to one byte more than the largest document the
/// shared reader reads, so the reader refuses a larger file itself.
fn read(file: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let bound = u64::try_from(MAXIMUM_DOCUMENT_BYTES + 1).unwrap_or(u64::MAX);
    crate::read_bounded_source_file(file, "breg.check.file-unreadable", label, bound).map_err(
        |refusal| {
            if refusal.code == "source.file.bounds" {
                // The reader refuses a document over its bound before reading
                // a byte of it, so a buffer one byte over stands in for the
                // file the bounded read stopped at, and the refusal is the
                // reader's own `yaml.too-large`.
                match Reader::new(label).scan(&vec![b'\n'; MAXIMUM_DOCUMENT_BYTES + 1]) {
                    Err(report) => Failure::Refused(report),
                    Ok(_) => unreachable!("the reader refuses a document over its bound"),
                }
            } else {
                Failure::unavailable(
                    "breg.check.file-unreadable",
                    "the file could not be read: it must be an existing regular file, reached by a path with no `..` and no symbolic link",
                    "Name a regular file that exists and that this user may read, by a path with no `..` and no symbolic link.",
                )
            }
        },
    )
}

fn in_file(mut diagnostic: Diagnostic, label: &str) -> Diagnostic {
    if diagnostic.source.is_none() {
        diagnostic.source = Some(Source {
            file: label.to_owned(),
            line: None,
            column: None,
        });
    }
    diagnostic
}

/// The project-relative location of a migration descriptor,
/// `modules/<module>/migrations/<id>/descriptor.json`, when the file's path
/// ends in one.
fn descriptor_location(file: &Path) -> Option<String> {
    let components = file
        .components()
        .map(|component| component.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()?;
    let tail = components.get(components.len().checked_sub(5)?..)?;
    (tail[0] == "modules" && tail[2] == "migrations" && tail[4] == "descriptor.json")
        .then(|| tail.join("/"))
}

fn schema_test_receipt(input: &Input<'_>) -> Result<Vec<Diagnostic>, Failure> {
    match fixtures::read_schema_test_receipt(input.document.file(), input.bytes) {
        Ok(_) => Ok(Vec::new()),
        Err(fixtures::FixtureError::ReceiptDocument(report)) => Err(Failure::Refused(report)),
        Err(error) => Ok(vec![input.document.diagnostic_at_value(
            Severity::Error,
            "breg.receipt.refused",
            "",
            &error.to_string(),
            "Run `bregctl test` again to write the receipt.",
        )]),
    }
}

/// A journeys document: its shape on its own, and its references against the
/// project when one is named.
fn journeys(input: &Input<'_>) -> Result<Vec<Diagnostic>, Failure> {
    fixtures::check_journeys_document(input.document)?;
    let Some(project) = input.project else {
        return Ok(vec![input.document.diagnostic_at_value(
            Severity::Warning,
            "breg.check.project-not-read",
            "",
            "the journeys were not checked against a project, so their access profiles, entities and references were not resolved",
            "Name the project before --file to check the journeys against it.",
        )]);
    };
    let registry =
        crate::compile(project, crate::ProfileArg::Authoring, "check").map_err(|_| {
            Failure::unavailable(
                "breg.check.project-refused",
                "the project does not compile, so the journeys were not checked against it",
                "Run `bregctl check PROJECT` and correct what it reports.",
            )
        })?;
    Ok(
        match fixtures::validate_fixture_journeys(input.bytes, &registry) {
            Ok(_) => Vec::new(),
            Err(fixtures::FixtureError::JourneyDocument(report)) => {
                return Err(Failure::Refused(report))
            }
            Err(error) => vec![journey_refusal(input.document, error)],
        },
    )
}

/// Place a journey refusal at the journey or step it concerns. The messages
/// name counts and identifiers the reader accepted, never a value.
fn journey_refusal(document: &Document, error: fixtures::FixtureError) -> Diagnostic {
    const ACTION: &str = "Correct the journeys as the message says, then check them again.";
    let (code, pointer, message) = match error {
        fixtures::FixtureError::JourneyRefused {
            journey_index,
            message,
            ..
        } => (
            "breg.journeys.journey",
            format!("/journeys/{journey_index}"),
            message,
        ),
        fixtures::FixtureError::StepFailed {
            journey_index,
            step_index,
            error,
        } => (
            "breg.journeys.step",
            format!("/journeys/{journey_index}/steps/{step_index}"),
            error.to_string(),
        ),
        fixtures::FixtureError::JourneyBoundsRefused => (
            "breg.journeys.bounds",
            "/journeys".to_owned(),
            error.to_string(),
        ),
        error => ("breg.journeys.refused", String::new(), error.to_string()),
    };
    diagnostic_near(document, code, &pointer, &message, ACTION)
}

/// An error about the member at `pointer`, placed at the nearest member the
/// document writes when that one is absent.
pub(crate) fn diagnostic_near(
    document: &Document,
    code: &str,
    pointer: &str,
    message: &str,
    suggested_action: &str,
) -> Diagnostic {
    let mut written = pointer;
    while document.span_of(written).is_none() {
        match written.rfind('/') {
            Some(slash) => written = &written[..slash],
            None => break,
        }
    }
    let mut diagnostic =
        document.diagnostic_at_value(Severity::Error, code, written, message, suggested_action);
    diagnostic.path = pointer.to_owned();
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_location_is_the_last_five_path_components() {
        assert_eq!(
            descriptor_location(Path::new(
                "/work/project/modules/core/migrations/add-rank/descriptor.json"
            ))
            .as_deref(),
            Some("modules/core/migrations/add-rank/descriptor.json")
        );
        assert_eq!(
            descriptor_location(Path::new(
                "modules/core/migrations/add-rank/descriptor.json"
            ))
            .as_deref(),
            Some("modules/core/migrations/add-rank/descriptor.json")
        );
        assert_eq!(descriptor_location(Path::new("/tmp/descriptor.json")), None);
        assert_eq!(
            descriptor_location(Path::new("/a/b/c/d/descriptor.json")),
            None
        );
    }

    #[test]
    fn every_format_is_checked_once() {
        let mut kinds = CHECKS
            .iter()
            .map(|(format, ..)| format.kind)
            .collect::<Vec<_>>();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), CHECKS.len());
    }
}
