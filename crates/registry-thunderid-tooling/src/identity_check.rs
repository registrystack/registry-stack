//! The offline check of the identity generator's two read formats
//! (CFG-CHECK-1): a product identity facts document and the operator's
//! identity deployment file, each identified by its `apiVersion`.
//!
//! A check reads the file through the shared reader and applies every rule
//! reading it for generation applies that needs no other input. For a
//! deployment it also reads the public key files the deployment names
//! (never a secret) and refuses a missing, malformed or private key file.
//! Given facts files, it runs the whole generation in memory and reports
//! the cross-file rules too (grants against admitted clients, claim types,
//! issuer), writing nothing.

use std::path::{Path, PathBuf};

use registry_platform_yaml::{Diagnostic, Expect, Reader, Report, Severity, Source};

use crate::check::{read_and_check, FileCheck};
use crate::identity_deployment::{self as deployment_file, IdentityDeployment};
use crate::identity_facts as facts_file;
use crate::identity_generate::{self as generate, key_file_refusal, read_bounded};
use crate::ToolingError;

/// Check the facts document or deployment file at `path`. `facts` are
/// product facts files to check a deployment against; they are ignored for a
/// facts document.
pub fn check_file(path: &Path, facts: &[PathBuf]) -> FileCheck {
    read_and_check(path, |file, bytes| check_bytes(file, bytes, path, facts))
}

fn check_bytes(file: &str, bytes: &[u8], path: &Path, facts: &[PathBuf]) -> Report {
    let formats = [facts_file::FORMAT, deployment_file::FORMAT];
    let mut hook = registry_platform_config::AuthoredExpressions;
    let document = match Reader::new(file)
        .with_hook(&mut hook)
        .read(bytes, &Expect::new(&formats))
    {
        Ok(document) => document,
        Err(report) => return report,
    };
    if document.envelope().kind == facts_file::KIND {
        return match facts_file::read(file, bytes) {
            Ok(_) => document.warnings(),
            Err(refused) => report_of(file, refused),
        };
    }
    let deployment = match deployment_file::read(file, bytes) {
        Ok((deployment, _)) => deployment,
        Err(refused) => return report_of(file, refused),
    };
    let mut report = document.warnings();
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let public_jwks = generate::read_public_jwks(base, &deployment);
    if facts.is_empty() {
        for (index, client) in deployment.clients.iter().enumerate() {
            let key_bytes = public_jwks.get(&client.public_jwks_file);
            if let Some((code, message, action)) = key_file_refusal(key_bytes.map(Vec::as_slice)) {
                report.push(document.diagnostic_at_value(
                    Severity::Error,
                    code,
                    &format!("/clients/{index}/publicJwksFile"),
                    message,
                    action,
                ));
            }
        }
        return report;
    }
    check_against_facts(file, bytes, facts, &deployment, &public_jwks, report)
}

/// Run the generation in memory over the deployment and the facts files.
fn check_against_facts(
    file: &str,
    bytes: &[u8],
    facts: &[PathBuf],
    _deployment: &IdentityDeployment,
    public_jwks: &std::collections::BTreeMap<String, Vec<u8>>,
    mut report: Report,
) -> Report {
    let mut labels = Vec::new();
    let mut contents = Vec::new();
    for path in facts {
        let label = path.display().to_string();
        match read_bounded(path) {
            Ok(content) => {
                labels.push(label);
                contents.push(content);
            }
            Err(_) => report.push(unreadable(&label)),
        }
    }
    if report.has_errors() {
        return report;
    }
    let sources: Vec<generate::Source<'_>> = labels
        .iter()
        .zip(&contents)
        .map(|(label, bytes)| generate::Source { label, bytes })
        .collect();
    let inputs = generate::Inputs {
        deployment: generate::Source { label: file, bytes },
        facts: &sources,
        public_jwks,
    };
    if let Err(refused) = generate::generate(&inputs) {
        report.extend(report_of(file, refused));
    }
    report
}

fn unreadable(file: &str) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        "platform.check.unreadable",
        "",
        "the file cannot be read",
        "Pass the path of an existing, readable file.",
    );
    diagnostic.source = Some(Source {
        file: file.to_owned(),
        line: None,
        column: None,
    });
    diagnostic
}

/// The findings of a refusal as a report. A refusal that carries no report
/// names a structural location, never a value.
fn report_of(file: &str, refused: ToolingError) -> Report {
    match refused {
        ToolingError::FileRefused { report, .. } => *report,
        ToolingError::IdentityRefused {
            code,
            message,
            location,
        } => {
            let mut diagnostic = Diagnostic::error(
                code,
                &location,
                message,
                "Correct the inputs named by the location, or regenerate the facts.",
            );
            diagnostic.source = Some(Source {
                file: file.to_owned(),
                line: None,
                column: None,
            });
            Report::new(vec![diagnostic])
        }
        ToolingError::InvalidDescription { reason } => {
            let mut diagnostic = Diagnostic::error(
                "platform.check.refused",
                "",
                reason,
                "Correct the deployment or facts inputs so the generated description is valid.",
            );
            diagnostic.source = Some(Source {
                file: file.to_owned(),
                line: None,
                column: None,
            });
            Report::new(vec![diagnostic])
        }
        _ => Report::new(vec![Diagnostic::error(
            "platform.check.internal-error",
            "",
            "the check could not complete",
            "Report this as a defect with the command line used.",
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/platform/examples/identity"
    );

    fn example(name: &str) -> PathBuf {
        Path::new(EXAMPLES).join(name)
    }

    #[test]
    fn an_input_caused_refusal_keeps_its_reason_and_a_generator_failure_does_not() {
        let report = report_of(
            "deployment.yaml",
            ToolingError::InvalidDescription {
                reason: "two derived identifiers are the same",
            },
        );
        assert_eq!(codes(&report), ["platform.check.refused"]);
        assert!(report.diagnostics()[0].message.contains("derived"));
        // A render failure is the generator's own (a serializer, an embedded
        // asset, its post-render assertion), not the operator's input.
        for failure in [
            ToolingError::InvalidRender {
                reason: "the rendered resources carry an unknown placeholder",
            },
            ToolingError::CommandFailed { step: "x" },
        ] {
            let report = report_of("deployment.yaml", failure);
            assert_eq!(codes(&report), ["platform.check.internal-error"]);
        }
    }

    fn codes(report: &Report) -> Vec<String> {
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    /// A copy of the example deployment with `keys/`, in a private directory.
    fn deployment_dir(edit: impl FnOnce(String) -> String) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let text = std::fs::read_to_string(example("identity-deployment.yaml")).unwrap();
        std::fs::write(dir.path().join("deployment.yaml"), edit(text)).unwrap();
        std::fs::create_dir(dir.path().join("keys")).unwrap();
        std::fs::copy(
            example("keys/case-portal.jwks.json"),
            dir.path().join("keys/case-portal.jwks.json"),
        )
        .unwrap();
        dir
    }

    #[test]
    fn the_committed_examples_pass() {
        for name in ["identity-facts.yaml", "identity-deployment.yaml"] {
            let checked = check_file(&example(name), &[]);
            assert!(!checked.unreadable, "{name}");
            assert!(checked.report.is_empty(), "{name}: {}", checked.report);
            assert_eq!(checked.report.files_checked(), Some(1), "{name}");
        }
    }

    #[test]
    fn the_example_deployment_passes_against_the_example_facts() {
        let checked = check_file(
            &example("identity-deployment.yaml"),
            &[example("identity-facts.yaml")],
        );
        assert!(
            !checked.report.has_errors(),
            "{}",
            checked.report.render_human()
        );
    }

    #[test]
    fn a_facts_document_is_checked_beyond_its_types() {
        let dir = tempfile::tempdir().unwrap();
        let text = std::fs::read_to_string(example("identity-facts.yaml")).unwrap();
        let path = dir.path().join("facts.yaml");
        std::fs::write(
            &path,
            text.replace("kind: PlatformIdentityFacts", "kind: Other"),
        )
        .unwrap();
        let checked = check_file(&path, &[]);
        assert_eq!(checked.report.error_count(), 1, "{}", checked.report);
    }

    #[test]
    fn a_private_key_file_is_refused() {
        let dir = deployment_dir(|text| text);
        let key = dir.path().join("keys/case-portal.jwks.json");
        std::fs::write(
            &key,
            r#"{"keys":[{"kty":"EC","crv":"P-256","d":"x","x":"a","y":"b"}]}"#,
        )
        .unwrap();
        let checked = check_file(&dir.path().join("deployment.yaml"), &[]);
        assert_eq!(
            codes(&checked.report),
            ["identity.deployment.private-key-material"]
        );
        let human = checked.report.render_human();
        assert!(!human.contains("\"d\""), "{human}");
    }

    #[test]
    fn a_missing_key_file_is_refused_with_its_member() {
        let dir = deployment_dir(|text| text);
        std::fs::remove_file(dir.path().join("keys/case-portal.jwks.json")).unwrap();
        let checked = check_file(&dir.path().join("deployment.yaml"), &[]);
        let diagnostics = checked.report.diagnostics();
        assert_eq!(diagnostics.len(), 1, "{}", checked.report);
        assert_eq!(diagnostics[0].code, "identity.deployment.missing-key-file");
        assert_eq!(diagnostics[0].path, "/clients/0/publicJwksFile");
        assert!(diagnostics[0].source.as_ref().unwrap().line.is_some());
    }

    #[test]
    fn a_grant_to_an_unadmitted_client_is_refused_against_facts() {
        let dir = deployment_dir(|text| text.replace("id: case-portal", "id: other-portal"));
        let checked = check_file(
            &dir.path().join("deployment.yaml"),
            &[example("identity-facts.yaml")],
        );
        assert!(checked.report.has_errors(), "{}", checked.report);
    }

    #[test]
    fn a_browser_application_without_room_for_the_actor_kind_is_refused_against_facts() {
        let names: Vec<String> = (1..=16).map(|n| format!("claim_{n:02}")).collect();
        let dir = deployment_dir(|text| {
            text.replace(
                "tokenAttributes: [registry_actor_kind, registry_principal]",
                &format!(
                    "tokenAttributes: [registry_principal, {}]",
                    names[1..].join(", ")
                ),
            )
        });
        let facts = dir.path().join("facts.yaml");
        let text = std::fs::read_to_string(example("identity-facts.yaml")).unwrap();
        let declared: String = names
            .iter()
            .map(|name| format!("  {name}: string\n"))
            .collect();
        std::fs::write(
            &facts,
            text.replace(
                "  registry_role: string\n",
                &format!("  registry_role: string\n{declared}"),
            ),
        )
        .unwrap();
        let checked = check_file(&dir.path().join("deployment.yaml"), &[facts]);
        // The example's BReg profile also requires a purpose, which the
        // full application has no room for either.
        assert_eq!(
            codes(&checked.report),
            [
                "identity.deployment.actor-kind-not-projected",
                "identity.deployment.purpose-not-projected"
            ]
        );
        assert!(checked
            .report
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.path == "/browserApps/0/tokenAttributes"));
    }

    #[test]
    fn a_principal_without_a_claim_its_profile_requires_is_refused_against_facts() {
        // BReg reads the example's principal from registry_principal and
        // refuses a token without it.
        let dir =
            deployment_dir(|text| text.replace("      registry_principal: officer-one\n", ""));
        let checked = check_file(
            &dir.path().join("deployment.yaml"),
            &[example("identity-facts.yaml")],
        );
        assert_eq!(
            codes(&checked.report),
            ["identity.deployment.required-claim-missing"]
        );
        assert_eq!(checked.report.diagnostics()[0].path, "/users/0/claims");
        let dir = deployment_dir(|text| text.replace(", registry_principal]", "]"));
        let checked = check_file(
            &dir.path().join("deployment.yaml"),
            &[example("identity-facts.yaml")],
        );
        assert_eq!(
            codes(&checked.report),
            ["identity.deployment.required-claim-not-projected"]
        );
    }

    #[test]
    fn a_browser_application_need_not_list_the_actor_kind_it_is_given() {
        let dir = deployment_dir(|text| {
            text.replace(
                "tokenAttributes: [registry_actor_kind, registry_principal]",
                "tokenAttributes: [registry_principal, registry_role]",
            )
        });
        let checked = check_file(
            &dir.path().join("deployment.yaml"),
            &[example("identity-facts.yaml")],
        );
        assert!(!checked.report.has_errors(), "{}", checked.report);
    }

    #[test]
    fn an_unreadable_facts_file_is_reported_not_skipped() {
        let dir = deployment_dir(|text| text);
        let checked = check_file(
            &dir.path().join("deployment.yaml"),
            &[dir.path().join("absent-facts.yaml")],
        );
        assert_eq!(codes(&checked.report), ["platform.check.unreadable"]);
    }

    #[test]
    fn a_secret_expression_is_refused_without_resolving_it() {
        let dir = deployment_dir(|text| {
            text.replace(
                "secret:env/STAFF_PORTAL_CLIENT_SECRET",
                "${SECRET_VALUE_NAME}",
            )
        });
        let checked = check_file(&dir.path().join("deployment.yaml"), &[]);
        assert!(checked.report.has_errors());
        assert!(!checked.report.render_human().contains("SECRET_VALUE_NAME"));
    }

    #[test]
    fn a_missing_file_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let checked = check_file(&dir.path().join("absent.yaml"), &[]);
        assert!(checked.unreadable);
    }
}
