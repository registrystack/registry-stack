// SPDX-License-Identifier: Apache-2.0

//! `caseworkctl check --against-breg-package`: whether a BReg source's pinned
//! `sourceRevision` is the registry revision a verified BReg package
//! rederives. The package is verified by the public `bregctl` of the same
//! release, never by linking the BReg crates.

use crate::project::{nameable, project_refusal, read_project};
use crate::source_add::{check_version, invoke, require_ok, shell_word};
use anyhow::{Context, Result};
use registry_casework_core::ConfigFinding;
use registry_platform_yaml::Related;
use serde_json::{json, Value};
use std::path::Path;

const OPERATION: &str = "check --against-breg-package";

/// Adds the `bregPackage` comparison to a completed check report, or refuses
/// a pin the package does not rederive with the repin and recheck commands.
/// Every refusal is placed in `casework.yaml` (CFG-DIAG-1) and names a source
/// id only when it is a valid identifier (CFG-SEC-3).
pub(super) fn compare(
    project: &Path,
    package: &Path,
    source_id: Option<&str>,
    bregctl_bin: &Path,
    mut report: Value,
) -> Result<Value> {
    let decoded = read_project(project)?;
    let policy = &decoded.value;
    let refuse =
        |finding: ConfigFinding| project_refusal(vec![finding.to_diagnostic(&decoded.document)]);
    let breg_sources = policy
        .sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.adapter == "breg")
        .collect::<Vec<_>>();
    let declared = || {
        breg_sources
            .iter()
            .map(|(index, source)| {
                nameable(&source.id)
                    .map_or_else(|| format!("the id at /sources/{index}/id"), str::to_owned)
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (index, source) = match (source_id, breg_sources.as_slice()) {
        (None, [only]) => *only,
        (None, []) => {
            return Err(refuse(ConfigFinding::new(
                "casework.source.none",
                "/sources",
                "the project declares no BReg source to compare with a BReg package",
                "Remove --against-breg-package, or declare a BReg source and run caseworkctl source add.",
            )))
        }
        (None, _) => {
            return Err(refuse(ConfigFinding::new(
                "casework.source.ambiguous",
                "/sources",
                "the project declares several BReg sources, so the one the package builds must be named with --source-id",
                format!(
                    "Rerun {} with --source-id set to one of: {}.",
                    check_command(project, package, None, bregctl_bin),
                    declared()
                ),
            )))
        }
        (Some(wanted), _) => match breg_sources.iter().find(|(_, source)| source.id == wanted) {
            Some(selected) => *selected,
            None => {
                return Err(refuse(ConfigFinding::new(
                    "casework.source.unknown",
                    "/sources",
                    nameable(wanted).map_or_else(
                        || "--source-id names no BReg source declared here".to_owned(),
                        |wanted| format!("--source-id {wanted} names no BReg source declared here"),
                    ),
                    format!(
                        "Rerun {} with --source-id set to one of: {}.",
                        check_command(project, package, None, bregctl_bin),
                        declared()
                    ),
                )))
            }
        },
    };
    let description_at = format!("/sources/{index}/description");
    let source_id = nameable(&source.id);
    let repin = repin_command(project, source_id, bregctl_bin);
    let unnamed = || {
        source_id.map_or_else(
            || format!(", where SOURCE_ID is the id at /sources/{index}/id"),
            |_| String::new(),
        )
    };
    let description = project.join(&source.description);
    if !description.is_file() {
        return Err(refuse(ConfigFinding::new(
            "casework.source-description.missing",
            description_at,
            "this source has no imported source description to compare",
            format!("Run {repin}{}.", unnamed()),
        )));
    }
    let bytes = std::fs::read(&description)
        .with_context(|| format!("reading {}", description.display()))?;
    let pinned = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|root| root["sourceRevision"].as_str().map(str::to_owned))
        .with_context(|| {
            format!(
                "source description {} names no sourceRevision",
                description.display()
            )
        })?;

    check_version(bregctl_bin, OPERATION)?;
    let verified = invoke(
        bregctl_bin,
        &["--format", "json", "check", "--package"],
        package,
    )?;
    require_ok("check --package", &verified)?;
    let rederived = verified["registryRevision"]
        .as_str()
        .context("bregctl check --package reported no registryRevision")?;
    let package_digest = verified["packageDigest"]
        .as_str()
        .context("bregctl check --package reported no packageDigest")?;
    if rederived != pinned {
        let mut diagnostic = ConfigFinding::new(
            "casework.source-revision.stale",
            description_at,
            "the imported source description pins a sourceRevision the BReg package does not rederive",
            format!(
                "Repin from the BReg project that built this package with {repin}, then rerun {}{}.",
                check_command(project, package, source_id.or(Some("SOURCE_ID")), bregctl_bin),
                unnamed()
            ),
        )
        .to_diagnostic(&decoded.document);
        diagnostic.related.push(Related {
            file: description.display().to_string(),
            line: None,
            column: None,
            path: "/sourceRevision".to_owned(),
            message: "the pinned revision is here".to_owned(),
        });
        return Err(project_refusal(vec![diagnostic]));
    }
    report
        .as_object_mut()
        .expect("check reports serialize as an object")
        .insert(
            "bregPackage".to_owned(),
            json!({
                "package": package,
                "packageDigest": package_digest,
                "registryRevision": rederived,
                "sourceId": source.id,
                "sourceRevision": pinned,
                "pin": "current",
            }),
        );
    Ok(report)
}

fn bregctl_argument(bregctl_bin: &Path) -> String {
    if bregctl_bin == Path::new("bregctl") {
        String::new()
    } else {
        format!(
            " --bregctl-bin {}",
            shell_word(&bregctl_bin.display().to_string())
        )
    }
}

/// The exact recheck, as the refusal names it.
pub(crate) fn check_command(
    project: &Path,
    package: &Path,
    source_id: Option<&str>,
    bregctl_bin: &Path,
) -> String {
    let mut command = format!(
        "caseworkctl check {} --against-breg-package {}",
        shell_word(&project.display().to_string()),
        shell_word(&package.display().to_string()),
    );
    if let Some(source_id) = source_id {
        command.push_str(" --source-id ");
        command.push_str(source_id);
    }
    command.push_str(&bregctl_argument(bregctl_bin));
    command
}

fn repin_command(project: &Path, source_id: Option<&str>, bregctl_bin: &Path) -> String {
    format!(
        "caseworkctl source add BREG_PROJECT --project {} --source-id {} --apply{}",
        shell_word(&project.display().to_string()),
        source_id.unwrap_or("SOURCE_ID"),
        bregctl_argument(bregctl_bin),
    )
}
