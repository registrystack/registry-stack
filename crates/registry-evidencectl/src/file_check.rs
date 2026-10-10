// SPDX-License-Identifier: Apache-2.0
//! `evidencectl check --file`: check one tooling file on its own.
//!
//! The file's `kind` names its format. A client profile or a reviewed
//! contracts file that still opens with the removed `schema` header is handed
//! to its reader, which refuses the header and names what to write. The
//! check reads the file with the reader its format has, applies the rules that
//! hold without a project, a session, a network or a secret, and reports what
//! it found in the shared diagnostic shape (CFG-DIAG-1, CFG-DIAG-2). It
//! resolves no secret reference (CFG-CHECK-1), writes nothing, and names no
//! value the file holds (CFG-SEC-3).

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::Path,
    process::ExitCode,
};

use registry_evidence_client::{
    read_client_profile, read_reviewed_contracts, EVIDENCE_CLIENT_CONTRACTS_KIND,
    EVIDENCE_CLIENT_PROFILE_KIND,
};
use registry_platform_yaml::{
    Diagnostic, NodeValue, Reader, Report, Source, MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::{json, Value};

use crate::{dev, report, source_import, OutputFormat};

type Check = fn(&str, &[u8]) -> Result<(), Failure>;

/// The `schema` header a client profile and a reviewed contracts file opened
/// with before the envelope, and the reader that refuses it by name.
const REMOVED_SCHEMA_HEADERS: [(&str, Check); 2] = [
    ("registry.evidence-client-contracts/v1", |file, bytes| {
        Ok(read_reviewed_contracts(file, bytes).map(drop)?)
    }),
    ("registry.evidence-client-profile/v1", |file, bytes| {
        Ok(read_client_profile(file, bytes).map(drop)?)
    }),
];

/// Every format the command reads, the `kind` that names it, whether the file
/// may exceed the shared reader's document bound, and its check. The two
/// source-import files embed project content, so the importer bounds them
/// itself and the reader never sees them.
const FORMATS: [(&str, bool, Check); 7] = [
    (EVIDENCE_CLIENT_CONTRACTS_KIND, false, |file, bytes| {
        Ok(read_reviewed_contracts(file, bytes).map(drop)?)
    }),
    (EVIDENCE_CLIENT_PROFILE_KIND, false, |file, bytes| {
        Ok(read_client_profile(file, bytes).map(drop)?)
    }),
    (dev::DEV_STATE_KIND, false, |file, bytes| {
        Ok(dev::check_state_document(file, bytes)?)
    }),
    (source_import::JOURNAL_KIND, true, |file, bytes| {
        let text = utf8(file, bytes)?;
        source_import_refusal(file, source_import::check_journal_file(text))
    }),
    (source_import::STATE_KIND, true, |file, bytes| {
        let text = utf8(file, bytes)?;
        source_import_refusal(file, source_import::check_state_file(text))
    }),
    (source_import::RESOLUTION_KIND, false, |file, bytes| {
        Ok(source_import::check_resolution_file(file, bytes)?)
    }),
    (source_import::EXPORT_KIND, false, |file, bytes| {
        Ok(source_import::check_export_manifest(file, bytes)?)
    }),
];

/// Why a check produced no verdict of "passed".
enum Failure {
    /// The file was read and refused.
    Refused(Report),
    /// The check could not run; the diagnostic says what stopped it.
    Unavailable(Box<Diagnostic>),
}

impl From<Report> for Failure {
    fn from(report: Report) -> Failure {
        Failure::Refused(report)
    }
}

impl From<source_import::DocumentRefused> for Failure {
    fn from(refused: source_import::DocumentRefused) -> Failure {
        Failure::Refused(refused.report)
    }
}

/// Check one file and write the verdict. Exits 0 when the file passes, 1
/// when it is refused, and 3 when the check could not run.
pub(crate) fn run(file: &Path, format: OutputFormat) -> ExitCode {
    let label = file.display().to_string();
    let (lead, report, exit) = match check(file, &label) {
        Ok(()) => (None, one_file(Vec::new()), report::SUCCESS_EXIT),
        Err(Failure::Refused(report)) => (
            Some("evidencectl check refused the file."),
            report,
            report::DOMAIN_REFUSAL_EXIT,
        ),
        Err(Failure::Unavailable(diagnostic)) => (
            Some("evidencectl check could not check the file."),
            one_file(vec![in_file(*diagnostic, &label)]),
            report::OPERATIONAL_FAILURE_EXIT,
        ),
    };
    match format {
        OutputFormat::Json => {
            let Value::Array(diagnostics) = report.to_json_value() else {
                unreachable!("a report's diagnostics are a JSON array");
            };
            crate::print_report(&match exit {
                report::SUCCESS_EXIT => {
                    report::success("check", "complete", json!({ "diagnostics": diagnostics }))
                }
                report::DOMAIN_REFUSAL_EXIT => {
                    report::refused("check", "refused", json!({ "diagnostics": diagnostics }))
                }
                _ => report::failure("check", exit, diagnostics),
            });
        }
        OutputFormat::Human => {
            // One sentence of the command's own, then the diagnostics and the
            // summary line unchanged.
            let written = match lead {
                None => write!(
                    std::io::stdout(),
                    "Check passed.\n{}",
                    report.render_human()
                ),
                Some(lead) => write!(std::io::stderr(), "{lead}\n{}", report.render_human()),
            };
            if written.is_err() {
                return ExitCode::from(report::OPERATIONAL_FAILURE_EXIT);
            }
        }
    }
    ExitCode::from(exit)
}

fn check(file: &Path, label: &str) -> Result<(), Failure> {
    let bytes = read(file)?;
    let (kind, schema) = if bytes.len() <= MAXIMUM_DOCUMENT_BYTES {
        let root = Reader::new(label).scan(&bytes)?;
        let member = |name: &str| {
            let node = root.as_ref()?.pointer(name)?;
            match &node.value {
                NodeValue::String(text) => Some(text.text.clone()),
                _ => None,
            }
        };
        (member("/kind"), member("/schema"))
    } else {
        // Only the importer's own files may exceed the reader's bound, so a
        // file this large names its kind in JSON or is refused for its size.
        let kind = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|document| document["kind"].as_str().map(str::to_owned));
        (kind, None)
    };
    let found = FORMATS
        .iter()
        .find(|(wanted, ..)| kind.as_deref() == Some(wanted));
    let Some((_, may_exceed_reader_bound, check)) = found else {
        if kind.is_none() {
            let removed = REMOVED_SCHEMA_HEADERS
                .iter()
                .find(|(header, _)| schema.as_deref() == Some(header));
            if let Some((_, refuse)) = removed {
                return refuse(label, &bytes);
            }
        }
        if bytes.len() > MAXIMUM_DOCUMENT_BYTES {
            // The reader refuses a document over its bound, naming the bound.
            Reader::new(label).scan(&bytes)?;
        }
        return Err(Failure::Refused(one_file(vec![unknown_format(label)])));
    };
    if bytes.len() > MAXIMUM_DOCUMENT_BYTES && !may_exceed_reader_bound {
        Reader::new(label).scan(&bytes)?;
    }
    check(label, &bytes)
}

/// The diagnostic for a file whose `kind` names no format this command
/// reads. It lists the kinds it does read.
fn unknown_format(label: &str) -> Diagnostic {
    let known: Vec<String> = FORMATS
        .iter()
        .map(|(kind, ..)| format!("kind {kind}"))
        .collect();
    in_file(
        Diagnostic::error(
            "evidence.check.unknown-format",
            "",
            "the file's root `kind` names no format this command checks",
            format!(
                "Name one of: {}. To check an authoring project, pass its directory without --file.",
                known.join(", ")
            ),
        ),
        label,
    )
}

/// Read the file, bounded to one byte more than the largest file any format
/// accepts, so a larger file is refused rather than held.
fn read(file: &Path) -> Result<Vec<u8>, Failure> {
    let unreadable = || {
        Failure::Unavailable(Box::new(Diagnostic::error(
            "evidence.check.file-unreadable",
            "",
            "the file could not be read: it must be an existing regular file that this user may read, of a size its format allows",
            "Name a regular file that exists and that this user may read.",
        )))
    };
    let mut handle = File::open(file).map_err(|_| unreadable())?;
    if !handle.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(unreadable());
    }
    let bound = source_import::MAX_CHECKED_FILE_BYTES;
    let mut bytes = Vec::new();
    (&mut handle)
        .take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > bound {
        return Err(unreadable());
    }
    Ok(bytes)
}

/// The file as text, for a format whose check takes text.
fn utf8<'a>(label: &str, bytes: &'a [u8]) -> Result<&'a str, Failure> {
    std::str::from_utf8(bytes).map_err(|_| {
        Failure::Refused(one_file(vec![in_file(
            Diagnostic::error(
                "evidence.check.source-import-file",
                "",
                "the file is not UTF-8 text",
                "Let evidencectl write the file again.",
            ),
            label,
        )]))
    })
}

/// The importer's refusals are static sentences that name their fix; carry
/// one as the file's diagnostic.
fn source_import_refusal(file: &str, outcome: anyhow::Result<()>) -> Result<(), Failure> {
    outcome.map_err(|error| {
        Failure::Refused(one_file(vec![in_file(
            Diagnostic::error(
                "evidence.check.source-import-file",
                "",
                error.to_string(),
                "Correct the file as the message says, or delete .evidence/source-imports and run evidencectl source import again.",
            ),
            file,
        )]))
    })
}

fn one_file(diagnostics: Vec<Diagnostic>) -> Report {
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    report
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
