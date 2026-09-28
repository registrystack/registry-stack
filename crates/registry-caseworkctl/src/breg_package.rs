// SPDX-License-Identifier: Apache-2.0

//! `caseworkctl check --against-breg-package`: whether a BReg source's pinned
//! `sourceRevision` is the registry revision a verified BReg package
//! rederives. The package is verified by the public `bregctl` of the same
//! release, never by linking the BReg crates.

use crate::project::{load_and_check_policy, DeniedFindings};
use crate::source_add::{check_version, invoke, require_ok, shell_word};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

const OPERATION: &str = "check --against-breg-package";

/// Adds the `bregPackage` comparison to a completed check report, or refuses
/// a pin the package does not rederive with the repin and recheck commands.
pub(super) fn compare(
    project: &Path,
    package: &Path,
    source_id: Option<&str>,
    bregctl_bin: &Path,
    mut report: Value,
) -> Result<Value> {
    let policy = load_and_check_policy(project)?;
    let breg_sources = policy
        .sources
        .iter()
        .enumerate()
        .filter(|(_, source)| source.adapter == "breg")
        .collect::<Vec<_>>();
    let declared = || {
        breg_sources
            .iter()
            .map(|(_, source)| source.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (index, source) = match (source_id, breg_sources.as_slice()) {
        (None, [only]) => *only,
        (None, []) => {
            return Err(refusal(
                "casework.source.none",
                "arguments",
                "the project declares no BReg source to compare with a BReg package".to_owned(),
                "Remove --against-breg-package, or declare a BReg source and run caseworkctl source add.".to_owned(),
            ))
        }
        (None, _) => {
            return Err(refusal(
                "casework.source.ambiguous",
                "arguments",
                format!(
                    "the project declares several BReg sources ({}); name the one the package builds with --source-id",
                    declared()
                ),
                format!(
                    "Rerun {} with --source-id set to one of: {}.",
                    check_command(project, package, None, bregctl_bin),
                    declared()
                ),
            ))
        }
        (Some(wanted), _) => match breg_sources.iter().find(|(_, source)| source.id == wanted) {
            Some(selected) => *selected,
            None => {
                return Err(refusal(
                    "casework.source.unknown",
                    "arguments",
                    format!(
                        "--source-id {wanted} names no BReg source of the project; declared: {}",
                        declared()
                    ),
                    format!(
                        "Rerun {} with --source-id set to one of: {}.",
                        check_command(project, package, None, bregctl_bin),
                        declared()
                    ),
                ))
            }
        },
    };
    let description_path = format!("casework.yaml:/sources/{index}/description");
    let repin = repin_command(project, &source.id, bregctl_bin);
    let description = project.join(&source.description);
    if !description.is_file() {
        return Err(refusal(
            "casework.source-description.missing",
            &description_path,
            format!(
                "source {} has no imported source description to compare",
                source.id
            ),
            format!("Run {repin}."),
        ));
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
        return Err(DeniedFindings(vec![json!({
            "severity": "error",
            "code": "casework.source-revision.stale",
            "artifact": "source_description",
            "path": description_path,
            "message": format!(
                "source {} pins sourceRevision {pinned}, but the BReg package rederives registry revision {rederived}",
                source.id
            ),
            "suggestedAction": format!(
                "Repin from the BReg project that built this package with {repin}, then rerun {}.",
                check_command(project, package, Some(&source.id), bregctl_bin)
            ),
        })])
        .into());
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

fn refusal(code: &str, path: &str, message: String, action: String) -> anyhow::Error {
    DeniedFindings(vec![json!({
        "severity": "error",
        "code": code,
        "artifact": if path == "arguments" { "command_arguments" } else { "casework_project" },
        "path": path,
        "message": message,
        "suggestedAction": action,
    })])
    .into()
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

fn repin_command(project: &Path, source_id: &str, bregctl_bin: &Path) -> String {
    format!(
        "caseworkctl source add BREG_PROJECT --project {} --source-id {source_id} --apply{}",
        shell_word(&project.display().to_string()),
        bregctl_argument(bregctl_bin),
    )
}
