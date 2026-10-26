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
    read_client_profile, read_reviewed_contracts, EVIDENCE_CLIENT_CONTRACTS_API_VERSION,
    EVIDENCE_CLIENT_CONTRACTS_KIND, EVIDENCE_CLIENT_PROFILE_API_VERSION,
    EVIDENCE_CLIENT_PROFILE_KIND,
};
use registry_platform_yaml::{
    ApiVersion, Diagnostic, EnvelopeRule, Expect, FormatSpec, NodeValue, Reader, Report, Source,
    MAXIMUM_DOCUMENT_BYTES,
};
use serde_json::{json, Value};

use crate::{access, dev, report, source_import, OutputFormat};

type Check = fn(&str, &[u8]) -> Result<Report, Failure>;

/// The `schema` header a client profile and a reviewed contracts file opened
/// with before the envelope, and the reader that refuses it by name.
const REMOVED_SCHEMA_HEADERS: [(&str, Check); 2] = [
    ("registry.evidence-client-contracts/v1", |file, bytes| {
        Ok(read_reviewed_contracts(file, bytes).map(|_| one_file(Vec::new()))?)
    }),
    ("registry.evidence-client-profile/v1", |file, bytes| {
        Ok(read_client_profile(file, bytes).map(|_| one_file(Vec::new()))?)
    }),
];

/// Every format the command reads, the `kind` that names it, whether the file
/// may exceed the shared reader's document bound, and its check. The two
/// source-import files embed project content, so the importer bounds them
/// itself and the reader never sees them.
macro_rules! tooling_format {
    ($kind:expr, $version:expr) => {
        FormatSpec {
            kind: $kind,
            envelope: EnvelopeRule::ApiVersionKind {
                api_versions: &[ApiVersion::current($version)],
                retired_api_versions: &[],
            },
            removed_keys: &[],
        }
    };
}

const FORMATS: [(FormatSpec<'static>, bool, Check); 9] = [
    (
        registry_platform_yaml::CHECK_ACCEPTANCES_FORMAT,
        false,
        |file, bytes| {
            let decoded = registry_platform_config::read_project_check_acceptances(file, bytes)?;
            Ok(decoded.document.report_with(Vec::new()))
        },
    ),
    (
        registry_evidence_authoring::formats::ACCESS_CLIENT,
        false,
        |file, bytes| Ok(access::check_client_document(file, bytes)?),
    ),
    (
        tooling_format!(
            EVIDENCE_CLIENT_CONTRACTS_KIND,
            EVIDENCE_CLIENT_CONTRACTS_API_VERSION
        ),
        false,
        |file, bytes| Ok(read_reviewed_contracts(file, bytes).map(|_| one_file(Vec::new()))?),
    ),
    (
        tooling_format!(
            EVIDENCE_CLIENT_PROFILE_KIND,
            EVIDENCE_CLIENT_PROFILE_API_VERSION
        ),
        false,
        |file, bytes| Ok(read_client_profile(file, bytes).map(|_| one_file(Vec::new()))?),
    ),
    (dev::DEV_STATE_FORMAT, false, |file, bytes| {
        Ok(dev::check_state_document(file, bytes).map(|()| one_file(Vec::new()))?)
    }),
    (
        tooling_format!(
            source_import::JOURNAL_KIND,
            source_import::JOURNAL_API_VERSION
        ),
        true,
        |file, bytes| {
            let text = utf8(file, bytes)?;
            source_import_refusal(file, source_import::check_journal_file(text))
        },
    ),
    (
        tooling_format!(source_import::STATE_KIND, source_import::STATE_API_VERSION),
        true,
        |file, bytes| {
            let text = utf8(file, bytes)?;
            source_import_refusal(file, source_import::check_state_file(text))
        },
    ),
    (source_import::RESOLUTION_FORMAT, false, |file, bytes| {
        Ok(source_import::check_resolution_file(file, bytes).map(|()| one_file(Vec::new()))?)
    }),
    (source_import::EXPORT_FORMAT, false, |file, bytes| {
        Ok(source_import::check_export_manifest(file, bytes).map(|()| one_file(Vec::new()))?)
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
pub(crate) fn run(file: &Path, format: OutputFormat, deny_warnings: bool) -> ExitCode {
    let label = file.display().to_string();
    let (lead, report, exit) = match apply_warning_policy(check(file, &label), deny_warnings) {
        Ok(report) => (None, report, report::SUCCESS_EXIT),
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

fn apply_warning_policy(
    outcome: Result<Report, Failure>,
    deny_warnings: bool,
) -> Result<Report, Failure> {
    outcome.and_then(|diagnostics| {
        if crate::check::refuses_warnings(&diagnostics, deny_warnings) {
            Err(Failure::Refused(diagnostics))
        } else {
            Ok(diagnostics)
        }
    })
}

fn check(file: &Path, label: &str) -> Result<Report, Failure> {
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
        .find(|(wanted, ..)| kind.as_deref() == Some(wanted.kind));
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
        // No format was selected. Let the shared envelope reader report missing
        // or unsupported kinds with the complete supported envelope list.
        let formats: Vec<_> = FORMATS.iter().map(|(format, ..)| *format).collect();
        Reader::new(label).read(&bytes, &Expect::new(&formats))?;
        unreachable!("a known valid kind would have selected its owning checker")
    };
    if bytes.len() > MAXIMUM_DOCUMENT_BYTES && !may_exceed_reader_bound {
        Reader::new(label).scan(&bytes)?;
    }
    check(label, &bytes)
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
fn source_import_refusal(file: &str, outcome: anyhow::Result<()>) -> Result<Report, Failure> {
    outcome.map(|()| one_file(Vec::new())).map_err(|error| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_check_acceptances_are_a_supported_tool_file() {
        let temporary = tempfile::tempdir().unwrap();
        let file = temporary.path().join("check-acceptances.yaml");
        std::fs::write(
            &file,
            "apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1\nkind: PlatformCheckAcceptances\nacceptances: []\n",
        )
        .unwrap();

        let report = check(&file, &file.display().to_string())
            .unwrap_or_else(|_| panic!("the shared acceptance format is a supported tool file"));
        assert!(!report.has_errors());
        assert!(report.diagnostics().is_empty());
    }

    #[test]
    fn standalone_file_warnings_are_preserved_and_obey_the_requested_policy() {
        let warning = || {
            one_file(vec![Diagnostic::warning(
                "config.retired-api-version",
                "/apiVersion",
                "this file uses a retired format version",
                "Use the current format version.",
            )])
        };
        let allowed = apply_warning_policy(Ok(warning()), false)
            .unwrap_or_else(|_| panic!("warnings may pass without denial"));
        assert_eq!(allowed.warning_count(), 1);
        let Err(Failure::Refused(refused)) = apply_warning_policy(Ok(warning()), true) else {
            panic!("the standalone file warning must refuse under --deny-warnings");
        };
        assert_eq!(refused.warning_count(), 1);
        assert_eq!(refused.diagnostics()[0].code, "config.retired-api-version");
    }
}
