//! Offline inspection uses the normalized project model and compiler.
use anyhow::Result;
use registry_platform_yaml::Report;
use serde_json::{json, Value};
use std::{io, path::Path};
#[derive(Debug)]
pub(crate) struct Checked {
    pub(crate) report: Value,
    pub(crate) diagnostics: Report,
}
pub(crate) fn check(project: &Path, target: Option<&Path>, production: bool) -> Result<Checked> {
    let target_path = target.map(crate::target::target_path);
    let target = target_path.as_deref();
    if production {
        let target = target
            .ok_or_else(|| anyhow::anyhow!("--production requires an explicit EvidenceTarget"))?;
        let bytes = crate::authored::read_authored_file(target, "EvidenceTarget")?;
        let target =
            registry_evidence_authoring::target::read_target(&target.to_string_lossy(), &bytes)?
                .value;
        if !matches!(
            target.assurance_profile.as_deref(),
            Some("production" | "evidence-grade")
        ) {
            anyhow::bail!("--production requires production or evidence-grade target assurance");
        }
    }
    let mut checked = crate::normalized::inspect(project, target, "check")?;
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
                crate::build::check_compiled_bundle(&evidence, &compiled.bundle_path, project)
            })();
            crate::build::make_tree_removable(stage.path())?;
            let result = result?;
            checked.report["proof"] = json!("compiled-target");
            checked.report["packageDigest"] = json!(result.package_digest);
            checked.report["definitionRevisions"] = json!(result.requirements.iter().map(|definition| json!({"requirement":definition.id,"configurationRevision":definition.configuration_revision})).collect::<Vec<_>>());
        } else {
            if production {
                return Err(crate::build::TargetDocumentDiagnostic {
                    code: "evidence.target.signing-key-missing",
                    path: format!("{}:/signer/publicJwkFile", path.display()),
                    message: "the production target's governed public signing key is missing"
                        .to_owned(),
                }
                .into());
            }
            checked.report["deploymentInputs"] =
                json!({"complete":false,"missing":["signer.publicJwkFile"]});
        }
    }
    Ok(checked)
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
    crate::report::refused(
        command,
        "refused",
        json!({"project":project,"target":target,"proof":"authoring","diagnostics":found.to_json_value(),"projectPresentation":null,"selectorProfiles":{},"capabilityCeilings":null,"assertionDefinitions":[],"sources":[],"functions":[],"authority":null,"offline":true,"networkAccess":false,"secretResolution":false,"fixtureExecution":false}),
    )
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
            writeln!(
                out,
                "  Acquisition: {}; derive: {}",
                definition["acquisition"], definition["derive"]["function"]
            )?;
            writeln!(
                out,
                "  Outputs: {}; grant ceiling: {}",
                definition["outputs"], definition["grantCeiling"]
            )?;
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
    #[test]
    fn production_requires_an_explicit_target() {
        assert!(check(Path::new("unused"), None, true).is_err());
    }
    #[test]
    fn explain_renders_named_definitions_functions_and_authority() {
        let report = json!({"command":"explain","status":"complete","project":"example","assertionDefinitions":[{"id":"active","requirement":"urn:example:active","acquisition":{"type":"single","source":"records"},"derive":{"function":"derive-active"},"outputs":{"active":{"type":"boolean"}},"grantCeiling":{"authorities":["organizational"]}}],"functions":[{"id":"derive-active","interface":"assertion-derive/v1","digest":"sha256:reviewed","callSites":["/assertionDefinitions/active/derive"],"inputs":["private-facts"],"outputs":["declared-outputs"],"capabilities":["declared-outputs"]}],"authority":{"authorityRevision":"sha256:active"}});
        let mut output = Vec::new();
        render_human(&report, &Report::new(Vec::new()), &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Definition active"));
        assert!(output.contains("Function derive-active"));
        assert!(output.contains("authorityRevision"));
    }
}
