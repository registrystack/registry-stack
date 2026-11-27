// SPDX-License-Identifier: Apache-2.0

//! `registry-session check`: the offline check of the runtime file (CFG-CHECK-1).
//! It reads the file as the service does and reports its findings in the shared
//! diagnostic shape, with no secret material, network call, audit file, or
//! listener. A secret the file names is resolved, and the audit directory
//! opened, only when the service starts.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

use registry_platform_yaml::{Diagnostic, Report, Source};
use serde::Serialize;

/// The `apiVersion` of the report `check --format json` writes.
pub const CTL_REPORT_API_VERSION: &str =
    "id.registrystack.org/formats/platform/session-ctl-report/v1alpha1";
/// The `kind` of the report `check --format json` writes.
pub const CTL_REPORT_KIND: &str = "PlatformSessionCtlReport";

/// Something was refused, or a warning was reported under `--deny-warnings`.
const DOMAIN_REFUSAL_EXIT: u8 = 1;
/// The runtime file could not be read at all (CFG-DIAG-4).
const OPERATIONAL_FAILURE_EXIT: u8 = 3;

/// How `check` writes what it found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Diagnostics in the shared human shape (CFG-DIAG-2).
    #[default]
    Human,
    /// One report object on standard output (CFG-DIAG-1).
    Json,
}

/// What one `registry-session check` run reads and how it reports.
#[derive(Debug)]
pub struct CheckRequest<'a> {
    /// The runtime file, as given on the command line.
    pub runtime: &'a Path,
    /// Substitute `${NAME}` expressions from the process environment and
    /// check every value.
    pub environment: bool,
    pub format: OutputFormat,
    pub deny_warnings: bool,
    /// The identity generator's receipt to cross-check the runtime file
    /// against.
    pub identity_receipt: Option<&'a Path>,
}

/// The report `check --format json` writes: the envelope members every ctl
/// report opens with, then the counts and every diagnostic.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CtlReport {
    ok: bool,
    command: &'static str,
    status: &'static str,
    api_version: &'static str,
    kind: &'static str,
    files_checked: usize,
    errors: usize,
    warnings: usize,
    diagnostics: serde_json::Value,
}

/// Run `registry-session check` and report every finding (CFG-DIAG-4): exit 0 when
/// nothing was refused, 1 when something was or a warning was reported under
/// `--deny-warnings`, and 3 when the file could not be read.
pub fn run(request: &CheckRequest<'_>, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let (mut diagnostics, mut unavailable) =
        check_runtime_file(request.runtime, request.environment);
    if let (Some(receipt), false) = (request.identity_receipt, diagnostics.iter().any(is_error)) {
        let (found, unreadable) = receipt_diagnostics(request.runtime, receipt);
        diagnostics.extend(found);
        unavailable |= unreadable;
    }
    let mut report = Report::new(diagnostics);
    report.set_files_checked(1);
    let exit = if unavailable {
        OPERATIONAL_FAILURE_EXIT
    } else if report.has_errors() || (request.deny_warnings && report.warning_count() > 0) {
        DOMAIN_REFUSAL_EXIT
    } else {
        0
    };
    match request.format {
        OutputFormat::Json => {
            let document = CtlReport {
                ok: exit == 0,
                command: "check",
                status: match exit {
                    0 => "complete",
                    OPERATIONAL_FAILURE_EXIT => "operational-failure",
                    _ => "domain-refusal",
                },
                api_version: CTL_REPORT_API_VERSION,
                kind: CTL_REPORT_KIND,
                files_checked: 1,
                errors: report.error_count(),
                warnings: report.warning_count(),
                diagnostics: report.to_json_value(),
            };
            let written = serde_json::to_writer_pretty(&mut *stdout, &document)
                .map_err(std::io::Error::other)
                .and_then(|()| writeln!(stdout));
            if written.is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human if exit == 0 => {
            if stdout.write_all(report.render_human().as_bytes()).is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
        OutputFormat::Human => {
            let sentence = if exit == OPERATIONAL_FAILURE_EXIT {
                "registry-session check could not read all of its input."
            } else {
                "registry-session check refused the input."
            };
            if write!(stderr, "{sentence}\n{}", report.render_human()).is_err() {
                return OPERATIONAL_FAILURE_EXIT;
            }
        }
    }
    exit
}

/// Check the runtime file at `path` as given: the loader needs an absolute,
/// lexically normal path, and every diagnostic names the file as given.
/// Returns the findings and whether the file could not be read at all.
fn check_runtime_file(path: &Path, environment: bool) -> (Vec<Diagnostic>, bool) {
    let given = path.display().to_string();
    let Some(absolute) = absolute_lexical(path) else {
        let mut diagnostic = Diagnostic::error(
            "platform.session-check.runtime-unreadable",
            "",
            "the runtime file path could not be made absolute",
            "Name the runtime file by an absolute path, then run the check again.",
        );
        diagnostic.source = Some(Source {
            file: given,
            line: None,
            column: None,
        });
        return (vec![diagnostic], true);
    };
    let checked = crate::config::check_runtime(&absolute, environment);
    let absolute = absolute.display().to_string();
    let diagnostics = checked
        .diagnostics
        .into_iter()
        .map(|mut diagnostic| {
            if let Some(source) = &mut diagnostic.source {
                if source.file == absolute {
                    source.file.clone_from(&given);
                }
            }
            for related in &mut diagnostic.related {
                if related.file == absolute {
                    related.file.clone_from(&given);
                }
            }
            diagnostic
        })
        .collect();
    (diagnostics, checked.unavailable)
}

/// `path` made absolute against the working directory, with `.` and `..`
/// resolved by name, as the runtime loader requires (CFG-ENV-5).
fn absolute_lexical(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut normal = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}

fn is_error(diagnostic: &Diagnostic) -> bool {
    Report::new(vec![diagnostic.clone()]).has_errors()
}

/// The largest receipt the check reads.
const MAXIMUM_RECEIPT_BYTES: u64 = 1024 * 1024;

fn receipt_diagnostic(code: &str, pointer: &str, message: &str, action: &str) -> Diagnostic {
    Diagnostic::error(code, pointer, message, action)
}

/// Cross-check the runtime file with the identity generator's receipt.
/// Returns the findings and whether the receipt could not be read at all.
fn receipt_diagnostics(runtime: &Path, receipt: &Path) -> (Vec<Diagnostic>, bool) {
    let unreadable = |reason: &str| {
        (
            vec![receipt_diagnostic(
                "platform.session-check.receipt-unreadable",
                "",
                reason,
                "Pass the identity-receipt.json the identity generator wrote.",
            )],
            true,
        )
    };
    let text = match std::fs::metadata(receipt) {
        Ok(metadata) if metadata.len() <= MAXIMUM_RECEIPT_BYTES => {
            match std::fs::read_to_string(receipt) {
                Ok(text) => text,
                Err(_) => return unreadable("the identity receipt could not be read"),
            }
        }
        Ok(_) => return unreadable("the identity receipt is larger than 1 MiB"),
        Err(_) => return unreadable("the identity receipt could not be read"),
    };
    let Ok(receipt) = serde_json::from_str::<serde_json::Value>(&text) else {
        return unreadable("the identity receipt is not JSON");
    };
    let Some(absolute) = absolute_lexical(runtime) else {
        return unreadable("the runtime file path could not be made absolute");
    };
    let config = match crate::config::RuntimeConfig::load(&absolute) {
        Ok(config) => config,
        Err(error) => {
            let mut found = error.diagnostics;
            found.push(receipt_diagnostic(
                "platform.session-check.receipt-needs-environment",
                "",
                "the runtime file could not be loaded with the process environment, so it cannot \
                 be compared with the receipt",
                "Set the variables the runtime file's `${NAME}` expressions name, then run the \
                 check again.",
            ));
            return (found, false);
        }
    };
    (receipt_findings(&config, &receipt), false)
}

/// The distinct audiences of a kind with the person audience first and the
/// others sorted, the form the receipt states.
fn receipt_order(person: Option<&str>, audiences: &[&str]) -> Vec<String> {
    let mut others: Vec<String> = audiences
        .iter()
        .filter(|audience| Some(**audience) != person)
        .map(|audience| (*audience).to_owned())
        .collect();
    others.sort();
    let mut ordered: Vec<String> = audiences
        .iter()
        .filter(|audience| Some(**audience) == person)
        .map(|audience| (*audience).to_owned())
        .collect();
    ordered.extend(others);
    ordered
}

/// Every difference between the runtime file's audiences and the receipt's.
/// The receipt states the person audience first and the others sorted, so the
/// runtime file's derived set is compared in that order: the order modules are
/// written in does not matter.
pub(crate) fn receipt_findings(
    config: &crate::config::RuntimeConfig,
    receipt: &serde_json::Value,
) -> Vec<Diagnostic> {
    let mut findings = Vec::new();
    let runtime_person = config
        .person_audience
        .as_ref()
        .map(|audience| audience.as_str());
    let receipt_person = receipt["personAudience"]["audience"].as_str();
    if runtime_person != receipt_person {
        findings.push(receipt_diagnostic(
            "platform.session-check.person-audience-mismatch",
            "/personAudience",
            &format!(
                "personAudience is {} in the runtime file and {} in the identity receipt",
                runtime_person.unwrap_or("absent"),
                receipt_person.unwrap_or("absent")
            ),
            "Make the runtime file's personAudience the one the identity deployment declares.",
        ));
    }
    for sign_in in &config.sign_ins {
        let client_id = sign_in.client_id.as_str();
        let pointer = format!("/signIns/{}", sign_in.id.as_str());
        let derived = receipt_order(runtime_person, &config.audience_set(sign_in.id.as_str()));
        let Some(stated) = receipt["sessionApps"][client_id]["audiences"].as_array() else {
            findings.push(receipt_diagnostic(
                "platform.session-check.sign-in-not-in-receipt",
                &pointer,
                &format!(
                    "the kind of sign-in {} uses a client the identity receipt does not list \
                     as a session application",
                    sign_in.id.as_str()
                ),
                "Declare the client as a session application in the identity deployment.",
            ));
            continue;
        };
        let stated: Vec<String> = stated
            .iter()
            .filter_map(|audience| audience.as_str().map(str::to_owned))
            .collect();
        if derived != stated {
            findings.push(receipt_diagnostic(
                "platform.session-check.audience-set-mismatch",
                &pointer,
                &format!(
                    "the kind of sign-in {} reaches the audiences [{}] in the runtime file and \
                     [{}] in the identity receipt",
                    sign_in.id.as_str(),
                    derived.join(", "),
                    stated.join(", ")
                ),
                "Make the modules this kind may call use the audiences the identity \
                 deployment grants its client.",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config() -> crate::config::RuntimeConfig {
        crate::config::tests::load(&crate::config::tests::document()).expect("config")
    }

    fn receipt() -> serde_json::Value {
        json!({
            "personAudience": {
                "audience": "https://api.example/person",
                "products": ["breg", "documents"]
            },
            "sessionApps": {
                "citizen-app": {
                    "products": ["breg"],
                    "audiences": ["https://api.example/person"]
                },
                "staff-app": {
                    "products": ["breg", "casework"],
                    "audiences": ["https://api.example/person", "https://casework.example/api"]
                }
            }
        })
    }

    fn codes(receipt: &serde_json::Value) -> Vec<String> {
        receipt_findings(&config(), receipt)
            .into_iter()
            .map(|finding| finding.code)
            .collect()
    }

    #[test]
    fn a_matching_receipt_passes() {
        assert_eq!(codes(&receipt()), Vec::<String>::new());
    }

    #[test]
    fn a_one_character_audience_typo_fails_and_names_both_values() {
        let mut receipt = receipt();
        receipt["sessionApps"]["staff-app"]["audiences"][1] = json!("https://casework.example/apj");
        let findings = receipt_findings(&config(), &receipt);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].code,
            "platform.session-check.audience-set-mismatch"
        );
        assert!(findings[0].message.contains("staff"));
        assert!(findings[0].message.contains("https://casework.example/api"));
        assert!(findings[0].message.contains("https://casework.example/apj"));
    }

    #[test]
    fn a_missing_and_an_extra_audience_each_fail() {
        let mut missing = receipt();
        missing["sessionApps"]["staff-app"]["audiences"] = json!(["https://api.example/person"]);
        assert_eq!(
            codes(&missing),
            ["platform.session-check.audience-set-mismatch"]
        );
        let mut extra = receipt();
        extra["sessionApps"]["citizen-app"]["audiences"] =
            json!(["https://api.example/person", "https://extra.example/api"]);
        assert_eq!(
            codes(&extra),
            ["platform.session-check.audience-set-mismatch"]
        );
    }

    #[test]
    fn a_different_person_audience_and_an_unlisted_client_fail() {
        let mut other = receipt();
        other["personAudience"]["audience"] = json!("https://api.example/persom");
        assert!(
            codes(&other).contains(&"platform.session-check.person-audience-mismatch".to_owned())
        );
        let mut unlisted = receipt();
        unlisted["sessionApps"]
            .as_object_mut()
            .expect("object")
            .remove("citizen-app");
        assert_eq!(
            codes(&unlisted),
            ["platform.session-check.sign-in-not-in-receipt"]
        );
    }

    #[test]
    fn the_order_modules_are_written_in_does_not_matter() {
        // The receipt states the person audience first and the others sorted.
        assert_eq!(
            receipt_order(Some("p"), &["z", "p", "a"]),
            ["p".to_owned(), "a".to_owned(), "z".to_owned()]
        );
    }
}
