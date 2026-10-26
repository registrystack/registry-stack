//! Offline inspection uses the normalized project model and compiler.
use anyhow::Result;
use registry_platform_yaml::{Diagnostic, Report};
use serde_json::{json, Value};
use std::{collections::BTreeSet, io, path::Path};
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) report: Value,
    pub(crate) diagnostics: Report,
}
pub(crate) fn check(
    project: &Path,
    target: Option<&Path>,
    production: bool,
    deny_warnings: bool,
) -> Result<Checked> {
    let target_path = target.map(crate::target::target_path);
    let target = target_path.as_deref();
    let assurance_refusal = if production {
        let path = target
            .ok_or_else(|| anyhow::anyhow!("--production requires an explicit EvidenceTarget"))?;
        let bytes = crate::authored::read_authored_file(path, "EvidenceTarget")?;
        let target_model =
            registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?
                .value;
        (!matches!(
            target_model.assurance_profile,
            Some(
                registry_evidence_authoring::target::TargetAssuranceProfile::Production
                    | registry_evidence_authoring::target::TargetAssuranceProfile::EvidenceGrade
            )
        ))
        .then(|| crate::build::TargetDocumentDiagnostic {
            code: "evidence.target.production-assurance-required",
            path: format!("{}:/assuranceProfile", path.display()),
            message: "--production requires production or evidence-grade target assurance"
                .to_owned(),
        })
    } else {
        None
    };
    let inspected_target = if assurance_refusal.is_some() {
        None
    } else {
        target
    };
    let mut checked = match crate::normalized::inspect(project, inspected_target, "check") {
        Ok(checked) => checked,
        Err(error) => {
            let Some(report) = error.downcast_ref::<Report>() else {
                return Err(error);
            };
            let mut report = report.clone();
            registry_platform_config::apply_check_acceptances(project, &mut report);
            if let Some(refusal) = &assurance_refusal {
                report.push(target_document_diagnostic(refusal));
            }
            return Err(report.into());
        }
    };
    registry_platform_config::apply_check_acceptances(project, &mut checked.diagnostics);
    if let Some(refusal) = &assurance_refusal {
        checked
            .diagnostics
            .push(target_document_diagnostic(refusal));
    }
    checked.report["diagnostics"] = checked.diagnostics.to_json_value();
    if checked.diagnostics.has_errors() {
        return Err(checked.diagnostics.into());
    }
    let target_check = (|| -> Result<()> {
        if let Some(path) = target {
            let bytes = crate::authored::read_authored_file(path, "EvidenceTarget")?;
            let target_model =
                registry_evidence_authoring::target::read_target(&path.to_string_lossy(), &bytes)?
                    .value;
            let root = crate::normalized::target_directory(path);
            let key = target_model.signer.public_jwk_file();
            if std::fs::symlink_metadata(root.join(key)).is_ok() {
                crate::normalized::safe_asset(root, key)?;
                let evidence = crate::evidence_binary::resolve_matching(None)?;
                let documents = crate::build::read_target_documents(path)?;
                let stage = tempfile::Builder::new()
                    .prefix("evidencectl-check-")
                    .tempdir()?;
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(stage.path(), std::fs::Permissions::from_mode(0o700))?;
                let stage_root = stage.path().canonicalize()?;
                let result = (|| {
                    let compiled = crate::build::compile_with_target(
                        project,
                        &documents,
                        &stage_root,
                        &evidence,
                        None,
                    )?;
                    crate::build::reject_review_markers(&compiled.bundle_path)?;
                    crate::build::check_compiled_bundle(
                        &evidence,
                        &compiled.bundle_path,
                        &compiled.runtime_path,
                        Some(path),
                        project,
                        &compiled.fixture_paths,
                    )
                })();
                crate::build::make_tree_removable(stage.path())?;
                let result = result?;
                checked.report["proof"] = json!("compiled-target");
                checked.report["packageDigest"] = json!(result.package_digest);
                checked.report["definitionRevisions"] = json!(result.requirements.iter().map(|definition| json!({"requirement":definition.id,"configurationRevision":definition.configuration_revision})).collect::<Vec<_>>());
            } else if production {
                return Err(crate::build::TargetDocumentDiagnostic {
                    code: "evidence.target.signing-key-missing",
                    path: format!("{}:/signer/publicJwkFile", path.display()),
                    message: "the production target's governed public signing key is missing"
                        .to_owned(),
                }
                .into());
            } else {
                checked.report["deploymentInputs"] =
                    json!({"complete":false,"missing":["signer.publicJwkFile"]});
            }
        }
        Ok(())
    })();
    if let Err(error) = target_check {
        return Err(merge_target_refusal(checked.diagnostics, error));
    }
    if refuses_warnings(&checked.diagnostics, deny_warnings) {
        return Err(checked.diagnostics.into());
    }
    Ok(checked)
}

fn merge_target_refusal(mut diagnostics: Report, error: anyhow::Error) -> anyhow::Error {
    if let Some(report) = crate::authored::report_in(&error) {
        diagnostics.extend(report.clone());
        return diagnostics.into();
    }
    if let Some(refusal) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::build::TargetDocumentDiagnostic>())
    {
        diagnostics.push(target_document_diagnostic(refusal));
        return diagnostics.into();
    }
    if let Some(refusal) = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::authoring::AuthoredDiagnostic>())
    {
        let mut diagnostic = crate::authored::compiler_diagnostic(refusal);
        diagnostic.artifact = Some("deployment-target".to_owned());
        diagnostics.push(diagnostic);
        return diagnostics.into();
    }
    error
}

fn target_document_diagnostic(refusal: &crate::build::TargetDocumentDiagnostic) -> Diagnostic {
    let mut diagnostic = Diagnostic::error(
        refusal.code,
        &refusal.path,
        &refusal.message,
        "Correct the selected project or target artifact and rerun check.",
    );
    diagnostic.artifact = Some("deployment-target".to_owned());
    diagnostic
}

pub(crate) fn refuses_warnings(diagnostics: &Report, deny_warnings: bool) -> bool {
    deny_warnings && diagnostics.warning_count() > 0
}
pub(crate) fn explain(project: &Path, target: Option<&Path>) -> Result<Checked> {
    crate::normalized::inspect(project, target, "explain")
}
pub(crate) fn refused_check_report(project: &Path, target: Option<&Path>, found: &Report) -> Value {
    refused("check", project, target, found)
}
pub(crate) fn refused_explain_report(
    project: &Path,
    target: Option<&Path>,
    found: &Report,
) -> Value {
    refused("explain", project, target, found)
}
fn refused(command: &str, project: &Path, target: Option<&Path>, found: &Report) -> Value {
    let status = if found
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.artifact.as_deref() == Some("deployment-target"))
    {
        "domain-refusal"
    } else {
        "refused"
    };
    crate::report::refused(
        command,
        status,
        json!({"project":project,"target":target,"proof":"authoring","diagnostics":found.to_json_value(),"projectPresentation":null,"selectorProfiles":{},"capabilityCeilings":null,"assertionDefinitions":[],"sources":[],"functions":[],"authority":null,"offline":true,"networkAccess":false,"secretResolution":false,"fixtureExecution":false}),
    )
}

fn object_keys(value: &Value) -> String {
    let mut keys = value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys())
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    if keys.is_empty() {
        "none".to_owned()
    } else {
        keys.join(", ")
    }
}

fn acquisition_source_ids(acquisition: &Value) -> Vec<&str> {
    match acquisition["type"].as_str() {
        Some("single") => acquisition["source"].as_str().into_iter().collect(),
        Some("search-then-fetch") => [
            acquisition["search"].as_str(),
            acquisition["fetch"].as_str(),
        ]
        .into_iter()
        .flatten()
        .collect(),
        Some("search-then-fetch-set") => acquisition["search"]
            .as_str()
            .into_iter()
            .chain(
                acquisition["fetch"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|fetch| fetch["source"].as_str()),
            )
            .collect(),
        _ => Vec::new(),
    }
}

fn render_source(source: &Value, out: &mut dyn io::Write) -> io::Result<()> {
    let id = source["id"].as_str().unwrap_or("unknown");
    let source_type = source["type"].as_str().unwrap_or("unknown");
    write!(out, "    Source {id}: {source_type}")?;
    if let (Some(method), Some(path)) = (
        source["operation"]["method"].as_str(),
        source["operation"]["path"].as_str(),
    ) {
        write!(out, " {method} {path}")?;
    }
    if let Some(connection) = source["connection"].as_str() {
        writeln!(out, "; connection {connection}")?;
    } else {
        writeln!(out, "; no named connection")?;
    }

    let preparation = if source["resolvedPreparation"]["generated"] == true {
        "generated".to_owned()
    } else if let Some(function) = source["prepare"]["function"].as_str() {
        format!("Function {function}")
    } else {
        "authored".to_owned()
    };
    writeln!(
        out,
        "      Prepare: {preparation}; extract: Function {}",
        source["extract"]["function"].as_str().unwrap_or("unknown")
    )?;
    writeln!(out, "      Facts: {}", object_keys(&source["facts"]))?;

    let attempt = source["limits"]["attemptTimeoutMilliseconds"].as_u64();
    let concurrency = source["limits"]["maximumConcurrency"].as_u64();
    let response_bytes = source["response"]["maximumBytes"].as_u64();
    if let (Some(attempt), Some(concurrency), Some(response_bytes)) =
        (attempt, concurrency, response_bytes)
    {
        writeln!(
            out,
            "      Limits: {attempt} ms attempt, {concurrency} concurrent, {response_bytes} bytes response"
        )?;
    }
    Ok(())
}

pub(crate) fn render_human(
    report: &Value,
    diagnostics: &Report,
    out: &mut dyn io::Write,
) -> io::Result<()> {
    writeln!(
        out,
        "Evidence project {}: {}",
        report["command"].as_str().unwrap_or("check"),
        report["status"].as_str().unwrap_or("unknown")
    )?;
    writeln!(
        out,
        "Project: {}",
        report["project"].as_str().unwrap_or(".")
    )?;
    if let Some(target) = report["target"].as_str() {
        writeln!(out, "Target: {target}")?;
    }
    if report["command"] == "explain" {
        let mut referenced_sources = BTreeSet::new();
        for definition in report["assertionDefinitions"]
            .as_array()
            .into_iter()
            .flatten()
        {
            writeln!(
                out,
                "Definition {}: {}",
                definition["id"].as_str().unwrap_or("unknown"),
                definition["requirement"].as_str().unwrap_or("unknown")
            )?;
            let acquisition = &definition["acquisition"];
            writeln!(
                out,
                "  Acquisition: {}",
                acquisition["type"].as_str().unwrap_or("unknown")
            )?;
            for source_id in acquisition_source_ids(acquisition) {
                referenced_sources.insert(source_id.to_owned());
                if let Some(source) = report["sources"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|source| source["id"].as_str() == Some(source_id))
                {
                    render_source(source, out)?;
                } else {
                    writeln!(out, "    Source {source_id}: unresolved")?;
                }
            }
            writeln!(
                out,
                "  Derive: Function {}",
                definition["derive"]["function"]
                    .as_str()
                    .unwrap_or("unknown")
            )?;
            writeln!(out, "  Outputs: {}", object_keys(&definition["outputs"]))?;
            writeln!(out, "  Grant ceiling: {}", definition["grantCeiling"])?;
        }
        let unreferenced_sources = report["sources"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|source| {
                source["id"]
                    .as_str()
                    .is_some_and(|id| !referenced_sources.contains(id))
            })
            .collect::<Vec<_>>();
        if !unreferenced_sources.is_empty() {
            writeln!(out, "Sources not referenced by definitions:")?;
            for source in unreferenced_sources {
                render_source(source, out)?;
            }
        }
        for function in report["functions"].as_array().into_iter().flatten() {
            writeln!(
                out,
                "Function {} ({}): {}",
                function["id"].as_str().unwrap_or("unknown"),
                function["interface"].as_str().unwrap_or("unknown"),
                function["digest"].as_str().unwrap_or("unknown")
            )?;
            writeln!(
                out,
                "  Call sites: {}; typed bindings: {}; capabilities: {}",
                function["callSites"], function["bindings"], function["capabilities"]
            )?;
        }
        if !report["authority"].is_null() {
            writeln!(out, "Target authority: {}", report["authority"])?;
        }
    }
    write!(out, "{}", diagnostics.render_human())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let destination = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &destination);
            } else {
                fs::copy(entry.path(), destination).unwrap();
            }
        }
    }
    #[test]
    fn production_requires_an_explicit_target() {
        assert!(check(Path::new("unused"), None, true, false).is_err());
    }
    #[test]
    fn deny_warnings_refuses_a_reported_warning_but_not_a_clean_report() {
        let clean = Report::new(Vec::new());
        let warning = Report::new(vec![registry_platform_yaml::Diagnostic::warning(
            "evidence.test.warning",
            "/test",
            "the test warning was reported",
            "Correct the test input.",
        )]);
        assert!(!refuses_warnings(&clean, true));
        assert!(!refuses_warnings(&warning, false));
        assert!(refuses_warnings(&warning, true));
    }
    #[test]
    fn check_reports_duplicate_display_text_and_deny_warnings_refuses_it() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        let project_file = temporary.path().join("evidence.yaml");
        let authored = fs::read_to_string(&project_file).unwrap().replacen(
            "  person-record:\n",
            "  person-record:\n    label: Registry source\n",
            1,
        );
        let authored = authored.replacen(
            "  licence-record:\n",
            "  licence-record:\n    label: registry source\n",
            1,
        );
        fs::write(&project_file, authored).unwrap();

        let checked = check(temporary.path(), None, false, false)
            .expect("warnings do not normally refuse check");
        assert_eq!(checked.diagnostics.error_count(), 0);
        assert_eq!(checked.diagnostics.warning_count(), 1);
        assert_eq!(
            checked.diagnostics.diagnostics()[0].code,
            "evidence.project.duplicate-source-label"
        );
        assert_eq!(
            checked.report["diagnostics"][0]["path"],
            "/sources/person-record/label"
        );
        assert_eq!(
            checked.report["diagnostics"][0]["source"]["file"],
            project_file.to_str().unwrap()
        );

        let error = check(temporary.path(), None, false, true)
            .expect_err("--deny-warnings refuses the warning");
        let report = error
            .downcast_ref::<Report>()
            .expect("a structured warning report");
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.warning_count(), 1);
        assert_eq!(
            report.diagnostics()[0].source.as_ref().unwrap().file,
            project_file.to_string_lossy()
        );

        fs::write(
            temporary.path().join("check-acceptances.yaml"),
            r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: evidence.project.duplicate-source-label
    scope:
      file: evidence.yaml
      path: /sources/person-record/label
    reason: These source labels are intentionally aligned for this reviewed project.
"#,
        )
        .unwrap();
        let accepted = check(temporary.path(), None, false, true)
            .expect("an accepted warning does not fail --deny-warnings");
        assert_eq!(accepted.diagnostics.error_count(), 0);
        assert_eq!(accepted.diagnostics.warning_count(), 0);
        assert_eq!(accepted.diagnostics.accepted_warning_count(), 1);
        assert_eq!(accepted.diagnostics.diagnostics().len(), 1);
        let warning = &accepted.diagnostics.diagnostics()[0];
        assert_eq!(warning.severity, registry_platform_yaml::Severity::Warning);
        assert_eq!(
            warning.scope.as_ref(),
            Some(&registry_platform_yaml::CheckScope {
                file: "evidence.yaml".to_owned(),
                path: "/sources/person-record/label".to_owned(),
            })
        );
        assert_eq!(
            warning.accepted_reason.as_deref(),
            Some("These source labels are intentionally aligned for this reviewed project.")
        );
        assert_eq!(
            accepted.report["diagnostics"][0]["acceptedReason"],
            "These source labels are intentionally aligned for this reviewed project."
        );
    }

    #[test]
    fn malformed_check_acceptances_refuse_the_evidence_project() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        fs::write(
            temporary.path().join("check-acceptances.yaml"),
            "apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1\nkind: PlatformCheckAcceptances\nacceptances: invalid\n",
        )
        .unwrap();

        let error = check(temporary.path(), None, false, false)
            .expect_err("a malformed acceptance file refuses the project");
        let report = error
            .downcast_ref::<Report>()
            .expect("malformed acceptances produce a structured diagnostic report");
        assert!(report.has_errors());
        assert!(report.diagnostics().iter().any(|diagnostic| {
            diagnostic
                .source
                .as_ref()
                .is_some_and(|source| source.file.ends_with("check-acceptances.yaml"))
        }));
    }
    #[test]
    fn check_preserves_duplicate_display_warning_when_function_compilation_fails() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        let project_file = temporary.path().join("evidence.yaml");
        let authored = fs::read_to_string(&project_file)
            .unwrap()
            .replacen(
                "  person-record:\n",
                "  person-record:\n    label: Registry source\n",
                1,
            )
            .replacen(
                "  licence-record:\n",
                "  licence-record:\n    label: registry source\n",
                1,
            );
        fs::write(&project_file, authored).unwrap();
        fs::write(
            temporary.path().join("functions/extract-person.rhai"),
            "fn extract(",
        )
        .unwrap();

        let error = check(temporary.path(), None, false, false)
            .expect_err("the Function error refuses a project that also warns");
        let report = error
            .downcast_ref::<Report>()
            .expect("a structured mixed report");
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 1);

        let compilation = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.function-compile")
            .expect("the Function compilation error is retained");
        assert_eq!(compilation.path, "/functions/0");
        let compilation_source = compilation.source.as_ref().expect("placed error");
        assert_eq!(compilation_source.file, project_file.to_string_lossy());
        assert_eq!(
            (compilation_source.line, compilation_source.column),
            (Some(13), Some(3))
        );

        let warning = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.duplicate-source-label")
            .expect("the duplicate display warning is retained");
        assert_eq!(warning.path, "/sources/person-record/label");
        let warning_source = warning.source.as_ref().expect("placed warning");
        assert_eq!(warning_source.file, project_file.to_string_lossy());
        assert!(warning_source.line.is_some());
        assert!(warning_source.column.is_some());

        fs::write(
            temporary.path().join("check-acceptances.yaml"),
            r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: evidence.project.duplicate-source-label
    scope:
      file: evidence.yaml
      path: /sources/person-record/label
    reason: These source labels are intentionally aligned for this reviewed project.
"#,
        )
        .unwrap();
        let error = check(temporary.path(), None, false, true)
            .expect_err("the Function error still refuses a project with an accepted warning");
        let report = error
            .downcast_ref::<Report>()
            .expect("the mixed refusal remains a structured report");
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 0);
        assert_eq!(report.accepted_warning_count(), 1);
        let warning = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.duplicate-source-label")
            .expect("the accepted warning remains beside the error");
        assert_eq!(
            warning.accepted_reason.as_deref(),
            Some("These source labels are intentionally aligned for this reviewed project.")
        );
    }
    #[test]
    fn check_preserves_an_accepted_warning_with_target_refusals() {
        for (assurance, refusal_code) in [
            (None, "evidence.target.production-assurance-required"),
            (Some("production"), "evidence.target.signing-key-missing"),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/evidence/examples/standalone");
            copy_tree(&source, temporary.path());
            let project_file = temporary.path().join("evidence.yaml");
            let authored = fs::read_to_string(&project_file)
                .unwrap()
                .replacen(
                    "  person-record:\n",
                    "  person-record:\n    label: Registry source\n",
                    1,
                )
                .replacen(
                    "  licence-record:\n",
                    "  licence-record:\n    label: registry source\n",
                    1,
                );
            fs::write(&project_file, authored).unwrap();
            fs::write(
                temporary.path().join("check-acceptances.yaml"),
                r#"apiVersion: id.registrystack.org/formats/platform/check-acceptances/v1alpha1
kind: PlatformCheckAcceptances
acceptances:
  - code: evidence.project.duplicate-source-label
    scope:
      file: evidence.yaml
      path: /sources/person-record/label
    reason: These source labels are intentionally aligned for this reviewed project.
"#,
            )
            .unwrap();
            if let Some(assurance) = assurance {
                let target_file = temporary.path().join("local-target.yaml");
                let authored = fs::read_to_string(&target_file).unwrap().replacen(
                    "project: standalone-evidence\n",
                    &format!("project: standalone-evidence\nassuranceProfile: {assurance}\n"),
                    1,
                );
                fs::write(target_file, authored).unwrap();
            } else {
                fs::remove_file(temporary.path().join("dev-authority.yaml")).unwrap();
            }

            let error = check(
                temporary.path(),
                Some(&temporary.path().join("local-target.yaml")),
                true,
                true,
            )
            .expect_err("the target refusal still refuses a project with an accepted warning");
            let report = error
                .downcast_ref::<Report>()
                .expect("the target refusal is merged into the project report");
            assert_eq!(report.error_count(), 1);
            assert_eq!(report.warning_count(), 0);
            assert_eq!(report.accepted_warning_count(), 1);
            assert!(report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == refusal_code));
            let warning = report
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "evidence.project.duplicate-source-label")
                .expect("the accepted warning remains beside the target refusal");
            assert_eq!(
                warning.accepted_reason.as_deref(),
                Some("These source labels are intentionally aligned for this reviewed project.")
            );
        }
    }
    #[test]
    fn merge_target_refusal_preserves_an_authored_domain_diagnostic() {
        let mut warning = registry_platform_yaml::Diagnostic::warning(
            "evidence.test.warning",
            "/test",
            "the accepted warning",
            "Review the warning.",
        );
        warning.accepted_reason = Some("Reviewed for this project.".to_owned());
        let error = merge_target_refusal(
            Report::new(vec![warning]),
            crate::authoring::AuthoredDiagnostic {
                code: "evidence.target.publication-invalid".to_owned(),
                path: "target.yaml:/publication".to_owned(),
                message: "the publication is invalid".to_owned(),
            }
            .into(),
        );

        let report = error
            .downcast_ref::<Report>()
            .expect("the authored target refusal is merged into the report");
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 0);
        assert_eq!(report.accepted_warning_count(), 1);
        let refusal = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.target.publication-invalid")
            .expect("the authored target refusal is retained");
        assert_eq!(refusal.path, "/publication");
        assert_eq!(
            refusal.source.as_ref().map(|source| source.file.as_str()),
            Some("target.yaml")
        );
        assert_eq!(refusal.artifact.as_deref(), Some("deployment-target"));
    }
    #[test]
    fn check_caps_project_warnings_with_a_function_compilation_error() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        let project_file = temporary.path().join("evidence.yaml");
        let authored = fs::read_to_string(&project_file).unwrap();
        let source_marker = "sources:\n";
        let mut repeated_functions = String::new();
        for index in 0..102 {
            repeated_functions.push_str(&format!(
                "- id: repeated-function-{index}\n  label: Indistinguishable Function label\n  interface: assertion-derive/v1\n  source: functions/derive-adult-status.rhai\n"
            ));
        }
        repeated_functions.push_str(source_marker);
        let authored = authored.replacen(source_marker, &repeated_functions, 1);
        assert_ne!(authored, fs::read_to_string(&project_file).unwrap());
        fs::write(&project_file, authored).unwrap();
        let function_file = temporary.path().join("functions/extract-person.rhai");
        fs::write(&function_file, "fn extract(").unwrap();

        let error = check(temporary.path(), None, false, false)
            .expect_err("the Function error refuses a project with excess warnings");
        let report = error
            .downcast_ref::<Report>()
            .expect("a bounded structured mixed report");
        assert_eq!(report.files_checked(), Some(1));
        assert_eq!(report.diagnostics().len(), 101);
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 100);
        assert_eq!(
            report.diagnostics()[0].code,
            "evidence.project.function-compile"
        );
        assert_eq!(report.diagnostics()[0].path, "/functions/0");
        assert_eq!(
            report.diagnostics()[0].source.as_ref().unwrap().file,
            project_file.to_string_lossy()
        );
        let overflow = report.diagnostics().last().unwrap();
        assert_eq!(overflow.code, "config.too-many-problems");
        assert_eq!(
            overflow.message,
            "2 more problems in this file are not shown"
        );

        let refused = refused_check_report(temporary.path(), None, report);
        let json = serde_json::to_string(&refused).unwrap();
        assert!(json.contains("evidence.project.function-compile"));
        assert!(json.contains("evidence.project.duplicate-function-label"));
        assert!(!json.contains("Indistinguishable Function label"));
        let mut human = Vec::new();
        render_human(&refused, report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("evidence.project.function-compile"));
        assert!(human.contains("evidence.project.duplicate-function-label"));
        assert!(!human.contains("Indistinguishable Function label"));
    }
    #[test]
    fn check_preserves_duplicate_display_warning_when_function_asset_is_missing() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        let project_file = temporary.path().join("evidence.yaml");
        let authored = fs::read_to_string(&project_file)
            .unwrap()
            .replacen(
                "  person-record:\n",
                "  person-record:\n    label: Registry source\n",
                1,
            )
            .replacen(
                "  licence-record:\n",
                "  licence-record:\n    label: registry source\n",
                1,
            );
        fs::write(&project_file, authored).unwrap();
        fs::remove_file(temporary.path().join("functions/extract-person.rhai")).unwrap();

        let error = check(temporary.path(), None, false, false)
            .expect_err("the absent Function asset prevents inspection");
        let report = error
            .downcast_ref::<Report>()
            .expect("the asset refusal keeps a structured mixed report");
        assert_eq!(report.error_count(), 1);
        assert_eq!(report.warning_count(), 1);

        let asset = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.asset-path")
            .expect("the missing asset is refused");
        assert_eq!(asset.path, "/functions/0/source");
        let asset_source = asset.source.as_ref().expect("placed asset refusal");
        assert_eq!(asset_source.file, project_file.to_string_lossy());
        assert_eq!(
            (asset_source.line, asset_source.column),
            (Some(15), Some(11))
        );

        let warning = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "evidence.project.duplicate-source-label")
            .expect("the duplicate display warning is retained");
        assert_eq!(warning.code, "evidence.project.duplicate-source-label");
        assert_eq!(warning.path, "/sources/person-record/label");
        let source = warning.source.as_ref().expect("placed warning");
        assert_eq!(source.file, project_file.to_string_lossy());
        assert!(source.line.is_some());
        assert!(source.column.is_some());

        let refused = refused_check_report(temporary.path(), None, report);
        assert_eq!(refused["diagnostics"].as_array().unwrap().len(), 2);
        let json = serde_json::to_string(&refused).unwrap();
        assert!(json.contains("evidence.project.asset-path"));
        assert!(json.contains("evidence.project.duplicate-source-label"));
        assert!(!json.contains("Registry source"));
        assert!(!json.contains("registry source"));

        let mut human = Vec::new();
        render_human(&refused, report, &mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("evidence.project.asset-path"));
        assert!(human.contains("evidence.project.duplicate-source-label"));
        assert!(!human.contains("Registry source"));
        assert!(!human.contains("registry source"));
    }
    #[test]
    fn check_reports_project_reader_errors_at_the_authored_file() {
        let temporary = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/standalone");
        copy_tree(&source, temporary.path());
        let project_file = temporary.path().join("evidence.yaml");
        let authored = fs::read_to_string(&project_file).unwrap().replacen(
            "id: standalone-evidence",
            "id: false",
            1,
        );
        fs::write(&project_file, authored).unwrap();

        let error = check(temporary.path(), None, false, false)
            .expect_err("the malformed project is refused");
        let report = error
            .downcast_ref::<Report>()
            .expect("a structured reader report");
        let diagnostic = report
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "config.expected-string")
            .expect("the malformed id is diagnosed");
        assert_eq!(
            diagnostic.source.as_ref().unwrap().file,
            project_file.to_string_lossy()
        );
    }
    #[test]
    fn explain_renders_the_ordered_source_to_output_flow_without_private_values() {
        let report = json!({
            "command":"explain",
            "status":"complete",
            "project":"example",
            "assertionDefinitions":[{
                "id":"eligible",
                "requirement":"urn:example:eligible",
                "acquisition":{
                    "type":"search-then-fetch-set",
                    "search":"records-search",
                    "fetch":[
                        {"source":"income-record","factInputs":["record-id"]},
                        {"source":"residence-record","factInputs":["record-id"]}
                    ],
                    "maximumAcquisitionMilliseconds":8000
                },
                "derive":{"function":"derive-eligible"},
                "outputs":{"eligible":{"type":"boolean"},"reason":{"type":"string"}},
                "grantCeiling":{"authorities":["organizational"]}
            }],
            "sources":[
                {
                    "id":"income-record",
                    "type":"http-json",
                    "connection":"benefits-api",
                    "operation":{"method":"GET","path":"/income/{record_id}"},
                    "facts":{"income":{"type":"integer"}},
                    "response":{"shape":{"const":"PRIVATE-SOURCE-CANARY"},"maximumBytes":32768},
                    "prepare":{"function":"prepare-income"},
                    "resolvedPreparation":{"generated":false},
                    "extract":{"function":"extract-income"},
                    "limits":{"attemptTimeoutMilliseconds":2000,"maximumConcurrency":4}
                },
                {
                    "id":"records-search",
                    "type":"http-json",
                    "connection":"registry-api",
                    "operation":{"method":"POST","path":"/records/search"},
                    "facts":{"record-id":{"type":"string"}},
                    "response":{"maximumBytes":65536},
                    "prepare":null,
                    "resolvedPreparation":{"generated":true},
                    "extract":{"function":"extract-search"},
                    "limits":{"attemptTimeoutMilliseconds":3000,"maximumConcurrency":8}
                },
                {
                    "id":"residence-record",
                    "type":"sqlite-extract",
                    "connection":null,
                    "operation":{"method":null,"path":null},
                    "facts":{"region":{"type":"string"}},
                    "response":{"maximumBytes":16384},
                    "prepare":null,
                    "resolvedPreparation":{"generated":true},
                    "extract":{"function":"extract-residence"},
                    "limits":{"attemptTimeoutMilliseconds":1000,"maximumConcurrency":2}
                },
                {
                    "id":"draft-source",
                    "type":"http-json",
                    "connection":"draft-api",
                    "operation":{"method":"GET","path":"/draft"},
                    "facts":{"draft-id":{"type":"string"}},
                    "response":{"maximumBytes":8192},
                    "prepare":null,
                    "resolvedPreparation":{"generated":true},
                    "extract":{"function":"extract-draft"},
                    "limits":{"attemptTimeoutMilliseconds":1000,"maximumConcurrency":1}
                }
            ],
            "functions":[{"id":"derive-eligible","interface":"assertion-derive/v1","digest":"sha256:reviewed","callSites":["/assertionDefinitions/eligible/derive"],"bindings":{},"capabilities":["declared-outputs"]}],
            "authority":{"authorityRevision":"sha256:active"}
        });
        let mut output = Vec::new();
        render_human(&report, &Report::new(Vec::new()), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        let search = output.find("Source records-search").expect("search source");
        let first_fetch = output
            .find("Source income-record")
            .expect("first fetch source");
        let second_fetch = output
            .find("Source residence-record")
            .expect("second fetch source");
        assert!(
            search < first_fetch && first_fetch < second_fetch,
            "{output}"
        );
        assert!(output.contains(
            "Source records-search: http-json POST /records/search; connection registry-api"
        ));
        assert!(output.contains("Prepare: generated; extract: Function extract-search"));
        assert!(output.contains(
            "Source income-record: http-json GET /income/{record_id}; connection benefits-api"
        ));
        assert!(
            output.contains("Prepare: Function prepare-income; extract: Function extract-income")
        );
        assert!(output.contains("Facts: income"));
        assert!(output.contains("Limits: 2000 ms attempt, 4 concurrent, 32768 bytes response"));
        assert!(output.contains("Derive: Function derive-eligible"));
        assert!(output.contains("Outputs: eligible, reason"));
        assert!(output.contains("Sources not referenced by definitions:"));
        assert!(output.contains("Source draft-source: http-json GET /draft; connection draft-api"));
        assert!(output.contains("Function derive-eligible"));
        assert!(output.contains("authorityRevision"));
        assert!(!output.contains("PRIVATE-SOURCE-CANARY"), "{output}");
    }
}
