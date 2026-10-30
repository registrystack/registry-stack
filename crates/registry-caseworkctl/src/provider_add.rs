// SPDX-License-Identifier: Apache-2.0
//! Compose a new Casework approval project from BReg's public inspection surface.
//!
//! This module never reads or writes BReg project files. It drives a same-version
//! `bregctl`, proposes source-authority changes for a person to apply, and writes
//! only a new Casework project after those changes are visible in the compiled
//! BReg explanation.

use anyhow::{Context, Result};
use registry_casework_breg::{BregContextExport, DESCRIPTION_API_VERSION, DESCRIPTION_KIND};
use registry_casework_core::{
    typed, ContentDigest, PolicySelection, ReviewContextContract, ReviewOutcomePolicy,
    ReviewStagePolicy,
};
use registry_platform_yaml::{Diagnostic, LocalId, Reader};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProviderAddState {
    ChangesNeeded,
    Created,
    InAgreement,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderAddChange {
    pub path: String,
    pub explanation: String,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "A bounded YAML fragment from the closed BReg authoring format; bregctl remains its format owner."))
    )]
    pub yaml: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderAddBypass {
    pub record_type: String,
    pub operation: String,
    pub profile: String,
    pub fields: Vec<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "A bounded mutationPolicy fragment from the closed BReg project format; bregctl remains its format owner."))
    )]
    pub mutation_policy: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderAddNotice {
    pub explanation: String,
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "A bounded YAML fragment from the closed BReg authoring format; bregctl remains its format owner."))
    )]
    pub yaml: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProviderAddData {
    pub project: PathBuf,
    pub action_id: String,
    pub pattern: String,
    pub outcome: ProviderAddState,
    pub source_namespace: String,
    pub policy_id: String,
    pub authority_id: String,
    pub provider_id: String,
    pub context_fields: Vec<String>,
    pub changes: Vec<ProviderAddChange>,
    pub deployment: Vec<ProviderAddChange>,
    pub bypass_paths: Vec<ProviderAddBypass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_grant: Option<ProviderAddNotice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_only_alternative: Option<ProviderAddNotice>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "The existing typed caseworkctl check payload is embedded unchanged."))
    )]
    pub check: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "The existing typed caseworkctl provider-pair agreement payload is embedded unchanged."))
    )]
    pub pairing: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-passthrough" = "The existing typed caseworkctl package payload is embedded unchanged."))
    )]
    pub package: Option<Value>,
    pub source_writes: bool,
    pub next: String,
}

/// Closed causes are rendered without peer command output or authored scalar values.
#[derive(Debug)]
pub(crate) enum ProviderAddFailure {
    VersionMismatch,
    BregctlRefused {
        command: &'static str,
    },
    InvalidReport {
        command: &'static str,
    },
    UnknownAction,
    WrongMode,
    EncryptedReviewContext {
        action_id: String,
    },
    ReviewContextBounds {
        action_id: String,
    },
    PolicyBindingMismatch {
        action_id: String,
    },
    PolicyIdUnsupported {
        action_id: String,
    },
    AmbiguousReviewerBoundaries {
        action_id: String,
        record_type: String,
    },
    ExistingMismatch {
        path: String,
        remedy: &'static str,
    },
    PackageDestinationExists,
    PackageDestinationIsProject,
    PackageDestinationTraversesProject,
    ExistingPackageOutputRequested,
    ExistingPackageOutputMismatch,
    BregPackageMismatch,
}

impl ProviderAddFailure {
    pub(crate) fn diagnostic(&self) -> (&'static str, String, &'static str, &'static str) {
        match self {
            Self::VersionMismatch => (
                "casework.provider-add.version-mismatch",
                "--bregctl-bin".into(),
                "bregctl must be the same Registry Stack release as caseworkctl",
                "Select a bregctl executable from the same Registry Stack release with --bregctl-bin, then run provider add again.",
            ),
            Self::BregctlRefused { command } => (
                "casework.provider-add.bregctl-refused",
                "--breg-project".into(),
                "bregctl refused a required inspection step",
                command,
            ),
            Self::InvalidReport { command } => (
                "casework.provider-add.invalid-breg-report",
                "--breg-project".into(),
                "bregctl returned no usable public explanation",
                command,
            ),
            Self::UnknownAction => (
                "casework.provider-add.action-not-found",
                "--action".into(),
                "the named Action is absent from the BReg project",
                "Run bregctl --format json explain actions BREG_PROJECT and select one declared Action, then run provider add again.",
            ),
            Self::WrongMode => (
                "casework.provider-add.action-not-proposal",
                "--action".into(),
                "the named Action is not in Proposal mode",
                "Decide whether changing this Action to Proposal mode is compatible with its callers; provider add does not change an Action execution mode.",
            ),
            Self::EncryptedReviewContext { action_id } => (
                "casework.provider-add.encrypted-review-context",
                format!("actions[id={action_id}].execution.proposal.reviewContext"),
                "this Action writes encrypted fields that BReg cannot disclose as before/after review context",
                "Author a supported reviewContext explicitly, choosing an inputs-only context if appropriate, then run provider add again. The default before/after context cannot be generated without changing what reviewers see.",
            ),
            Self::ReviewContextBounds { action_id } => (
                "casework.provider-add.review-context-bounds",
                format!("actions[id={action_id}].execution.proposal.reviewContext"),
                "the default review context exceeds BReg's 64-field context or changes-projection limit",
                "Author a minimized reviewContext with at most 64 context fields and at most 64 selected fields in each changes projection, then run provider add again. No fields are silently omitted.",
            ),
            Self::PolicyBindingMismatch { action_id } => (
                "casework.provider-add.policy-binding-mismatch",
                format!("actions[id={action_id}].execution.proposal.review.policy"),
                "the BReg policy selection does not match the compiled Casework approval policy",
                "Inspect the intended Casework policy binding with caseworkctl explain. Select that exact version and digest in BReg, or deliberately use an ID-only selection, then run provider add again.",
            ),
            Self::PolicyIdUnsupported { action_id } => (
                "casework.provider-add.policy-id-unsupported",
                format!("actions[id={action_id}].execution.proposal.review.policy.id"),
                "the BReg review policy identifier cannot be represented by a Casework project",
                "Choose a review policy ID with 1 to 64 lowercase letters, digits, underscores, or hyphens, starting with a letter, then run provider add again. The policy identity is never normalized or aliased.",
            ),
            Self::AmbiguousReviewerBoundaries {
                action_id,
                record_type,
            } => (
                "casework.provider-add.ambiguous-reviewer-boundaries",
                format!(
                    "actions[id={action_id}].permissions.targets[recordType={record_type}].rowBoundaries"
                ),
                "the Action's alternative profiles have different row boundary sets, so an explicit reviewer grant is required",
                "Author the reviewer's Proposal context and records.get permissions with the intended row boundaries, then run provider add again.",
            ),
            Self::ExistingMismatch { path, remedy } => (
                "casework.provider-add.existing-project-mismatch",
                path.clone(),
                "the existing Casework project does not agree with the selected BReg Action and approval pattern",
                remedy,
            ),
            Self::PackageDestinationExists => (
                "casework.provider-add.package-destination-exists",
                "--package-output".into(),
                "the package destination already exists",
                "Choose a new package output directory; provider add never overwrites package output.",
            ),
            Self::PackageDestinationIsProject => (
                "casework.provider-add.package-destination-is-project",
                "--package-output".into(),
                "the package output cannot replace the Casework project destination",
                "Choose a package output below the new project, such as PROJECT/.casework/package, or a separate new directory.",
            ),
            Self::PackageDestinationTraversesProject => (
                "casework.provider-add.package-destination-traverses-project",
                "--package-output".into(),
                "the package output leaves the new project through a parent path component",
                "Use the direct sibling package output path instead of spelling it through PROJECT/.. .",
            ),
            Self::ExistingPackageOutputRequested => (
                "casework.provider-add.existing-package-output-refused",
                "--package-output".into(),
                "provider add does not write package output when validating an existing project",
                "Run caseworkctl package PROJECT --output PACKAGE_OUTPUT explicitly after provider add confirms agreement.",
            ),
            Self::ExistingPackageOutputMismatch => (
                "casework.provider-add.existing-package-output-mismatch",
                "--package-output".into(),
                "the existing package output does not match the planned Casework package",
                "Choose a new package output path and run caseworkctl package PROJECT --output PACKAGE_OUTPUT explicitly; provider add never overwrites package output.",
            ),
            Self::BregPackageMismatch => (
                "casework.provider-add.breg-package-mismatch",
                "--breg-package".into(),
                "the sealed BReg package does not match the selected BReg project",
                "Repackage the selected BReg project and pass that sealed package, or select the BReg project that produced this package, then run provider add again.",
            ),
        }
    }
}

impl std::fmt::Display for ProviderAddFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic().2)
    }
}

impl std::error::Error for ProviderAddFailure {}

#[derive(Clone, Debug)]
struct WriteShape {
    record_type: String,
    operation: String,
    fields: BTreeSet<String>,
}

#[derive(Debug)]
struct AddPlan {
    action: Value,
    source_namespace: String,
    policy_id: String,
    policy_selection: PolicySelection,
    authority_id: String,
    context_fields: Vec<String>,
    changes: Vec<ProviderAddChange>,
    deployment: Vec<ProviderAddChange>,
    bypass_paths: Vec<ProviderAddBypass>,
    read_grant: Option<ProviderAddNotice>,
    inputs_only_alternative: Option<ProviderAddNotice>,
    service_profile: String,
    service_scopes: Vec<String>,
}

fn bregctl_version(bregctl: &Path) -> Result<()> {
    let output = Command::new(bregctl)
        .arg("--version")
        .output()
        .context("starting bregctl")?;
    if !output.status.success() {
        return Err(ProviderAddFailure::BregctlRefused {
            command:
                "Run bregctl --version by hand, correct that failure, and run provider add again.",
        }
        .into());
    }
    let version = std::str::from_utf8(&output.stdout)
        .unwrap_or_default()
        .trim();
    if !version.ends_with(registry_platform_buildinfo::DISPLAY_VERSION) {
        return Err(ProviderAddFailure::VersionMismatch.into());
    }
    Ok(())
}

fn explain(bregctl: &Path, project: &Path, subject: &'static str) -> Result<Value> {
    let output = Command::new(bregctl)
        .args(["--format", "json", "explain", subject])
        .arg(project)
        .output()
        .with_context(|| format!("starting bregctl explain {subject}"))?;
    let command = match subject {
        "proposals" => "Run bregctl --format json explain proposals BREG_PROJECT by hand, correct the named BReg project, and run provider add again.",
        "actions" => "Run bregctl --format json explain actions BREG_PROJECT by hand, correct the named BReg project, and run provider add again.",
        "access" => "Run bregctl --format json explain access BREG_PROJECT by hand, correct the named BReg project, and run provider add again.",
        _ => "Run the refused bregctl explain command by hand, correct the named BReg project, and run provider add again.",
    };
    if !output.status.success() {
        return Err(crate::child_report_failure(
            output.status,
            ProviderAddFailure::BregctlRefused { command },
        ));
    }
    let report: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| ProviderAddFailure::InvalidReport { command })?;
    if report["ok"] != true || !report["explanation"].is_object() {
        return Err(ProviderAddFailure::InvalidReport { command }.into());
    }
    Ok(report["explanation"].clone())
}

// BReg owns the report envelope and findings. Require the fields that establish
// this comparison without closing the peer product's full report here.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BregPackageDiffReport {
    ok: bool,
    command: String,
    profile: String,
    baseline_assurance: String,
    baseline_registry_revision: ContentDigest,
    candidate_registry_revision: ContentDigest,
}

const BREG_DIFF_COMMAND: &str = "Run bregctl --format json diff BREG_PROJECT --package BREG_PACKAGE by hand, correct the named BReg project or package, and run provider add again.";

fn decode_breg_package_diff_report(
    bytes: &[u8],
) -> std::result::Result<BregPackageDiffReport, ProviderAddFailure> {
    let report: BregPackageDiffReport =
        serde_json::from_slice(bytes).map_err(|_| ProviderAddFailure::InvalidReport {
            command: BREG_DIFF_COMMAND,
        })?;
    if !report.ok
        || report.command != "diff"
        || report.profile != "authoring"
        || report.baseline_assurance != "integrity-only"
    {
        return Err(ProviderAddFailure::InvalidReport {
            command: BREG_DIFF_COMMAND,
        });
    }
    Ok(report)
}

fn breg_package_agrees_with_project(bregctl: &Path, project: &Path, package: &Path) -> Result<()> {
    let output = Command::new(bregctl)
        .args(["--format", "json", "diff"])
        .arg(project)
        .arg("--package")
        .arg(package)
        .output()
        .context("starting bregctl diff")?;
    if !output.status.success() {
        return Err(crate::child_report_failure(
            output.status,
            ProviderAddFailure::BregctlRefused {
                command: BREG_DIFF_COMMAND,
            },
        ));
    }
    let report = decode_breg_package_diff_report(&output.stdout)?;
    if report.baseline_registry_revision != report.candidate_registry_revision {
        return Err(ProviderAddFailure::BregPackageMismatch.into());
    }
    Ok(())
}

fn generated_export(
    generated: &Path,
    action: &str,
    source_namespace: &str,
) -> Result<(BregContextExport, PathBuf)> {
    let index_path = generated.join("generated/review-context-schemas/index.json");
    let index: Value = serde_json::from_slice(&fs::read(&index_path).map_err(|_| {
        ProviderAddFailure::InvalidReport {
            command: "Run bregctl --format json generate schemas BREG_PROJECT --output DIRECTORY by hand and correct the named project.",
        }
    })?)?;
    let contract = &index[action];
    let relative = contract["path"].as_str().ok_or(ProviderAddFailure::InvalidReport {
        command: "Run bregctl --format json generate schemas BREG_PROJECT --output DIRECTORY by hand and confirm that the Action exports a review-context schema.",
    })?;
    let schema_path = generated.join(relative);
    let schema_bytes = fs::read(&schema_path)?;
    let schema_text = String::from_utf8(schema_bytes.clone())?;
    let schema: Value = serde_json::from_slice(&schema_bytes)?;
    let export = BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: source_namespace.into(),
        action_id: action.into(),
        context_id: schema["x-registry-review-context"]["contextId"]
            .as_str()
            .context("generated review-context schema has no context ID")?
            .into(),
        contract: ReviewContextContract {
            id: contract["id"]
                .as_str()
                .context("generated review-context schema has no contract ID")?
                .into(),
            revision: ContentDigest::parse(
                contract["revision"]
                    .as_str()
                    .context("generated review-context schema has no revision")?,
            )?,
            schema_digest: ContentDigest::parse(
                contract["digest"]
                    .as_str()
                    .context("generated review-context schema has no digest")?,
            )?,
        },
        schema,
        schema_bytes: schema_text,
    };
    export.check()?;
    Ok((export, schema_path))
}

fn generate_schemas(bregctl: &Path, project: &Path, output: &Path) -> Result<()> {
    let generated = Command::new(bregctl)
        .args(["--format", "json", "generate", "schemas"])
        .arg(project)
        .arg("--output")
        .arg(output)
        .output()
        .context("starting bregctl generate schemas")?;
    if !generated.status.success() {
        return Err(ProviderAddFailure::BregctlRefused {
            command: "Run bregctl --format json generate schemas BREG_PROJECT --output DIRECTORY by hand, correct the named BReg project, and run provider add again.",
        }
        .into());
    }
    let report: Value = serde_json::from_slice(&generated.stdout).map_err(|_| {
        ProviderAddFailure::InvalidReport {
            command: "Run bregctl --format json generate schemas BREG_PROJECT --output DIRECTORY by hand and inspect its report.",
        }
    })?;
    if report["ok"] != true {
        return Err(ProviderAddFailure::InvalidReport {
            command: "Run bregctl --format json generate schemas BREG_PROJECT --output DIRECTORY by hand and inspect its report.",
        }
        .into());
    }
    Ok(())
}

fn local_id(base: &str, suffix: &str) -> String {
    let maximum_base = 64usize.saturating_sub(suffix.len() + 1);
    let mut prefix = base.chars().take(maximum_base).collect::<String>();
    while prefix.ends_with('-') || prefix.ends_with('_') {
        prefix.pop();
    }
    format!("{prefix}-{suffix}")
}

fn normalized_nested_package_path(relative: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir => {
                return Err(ProviderAddFailure::PackageDestinationTraversesProject.into());
            }
            Component::RootDir | Component::Prefix(_) => unreachable!("stripped path is relative"),
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(ProviderAddFailure::PackageDestinationIsProject.into());
    }
    Ok(normalized)
}

fn nested_package_path(project: &Path, output: &Path) -> Result<Option<PathBuf>> {
    // Preserve an explicitly project-relative parent traversal as a refusal,
    // then compare mixed relative/absolute spellings in one coordinate system.
    if let Ok(relative) = output.strip_prefix(project) {
        return normalized_nested_package_path(relative).map(Some);
    }
    let absolute_project = std::path::absolute(project)?;
    let absolute_output = std::path::absolute(output)?;
    let Ok(relative) = absolute_output.strip_prefix(&absolute_project) else {
        return Ok(None);
    };
    normalized_nested_package_path(relative).map(Some)
}

fn absolute_parent(path: &Path, missing: &'static str) -> Result<PathBuf> {
    std::path::absolute(path)?
        .parent()
        .map(Path::to_path_buf)
        .context(missing)
}

fn public_name(id: &str) -> String {
    let mut name = String::new();
    let mut uppercase = false;
    for character in id.chars() {
        if character == '-' || character == '_' {
            uppercase = true;
        } else if uppercase {
            name.extend(character.to_uppercase());
            uppercase = false;
        } else {
            name.push(character);
        }
    }
    name
}

fn reserved_context_name(name: &str) -> bool {
    matches!(
        name,
        "id" | "record_id"
            | "recordId"
            | "revision"
            | "created_at"
            | "createdAt"
            | "updated_at"
            | "updatedAt"
            | "deleted_at"
            | "deletedAt"
    )
}

fn allocate_context_name(stem: &str, semantic_suffix: &str, used: &mut BTreeSet<String>) -> String {
    for sequence in 1_u32.. {
        let collision_suffix = if sequence == 1 {
            String::new()
        } else {
            sequence.to_string()
        };
        let maximum_stem = 64 - semantic_suffix.len() - collision_suffix.len();
        let mut candidate = stem.chars().take(maximum_stem).collect::<String>();
        candidate.push_str(semantic_suffix);
        candidate.push_str(&collision_suffix);
        if !reserved_context_name(&candidate) && used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("the finite context field set cannot exhaust numeric suffixes")
}

fn action_by_id<'a>(explanation: &'a Value, action: &str) -> Option<&'a Value> {
    explanation["actions"]
        .as_array()?
        .iter()
        .find(|candidate| candidate["id"].as_str() == Some(action))
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn used_inputs(action: &Value) -> Vec<String> {
    let known = action["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|input| input["id"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut found = strings(&action["plan"]["function"]["boundInputs"]);
    // Only compiler-owned reference positions name inputs. Literal JSON values
    // may contain an unrelated member named `input` and must remain opaque.
    if action["plan"]["type"].as_str() == Some("fixed") {
        for effect in action["plan"]["effects"].as_array().into_iter().flatten() {
            let binding = &effect["target"]["binding"];
            if binding["kind"].as_str() == Some("existing") {
                if let Some(input) = binding["input"].as_str() {
                    found.insert(input.to_owned());
                }
            }
            for mutation in effect["mutations"].as_array().into_iter().flatten() {
                let value = &mutation["value"];
                if value["kind"].as_str() == Some("from-input") {
                    if let Some(input) = value["input"].as_str() {
                        found.insert(input.to_owned());
                    }
                }
            }
        }
    }
    for guard in action["commitGuards"].as_array().into_iter().flatten() {
        for member in ["input", "equalsInput"] {
            if let Some(input) = guard[member].as_str() {
                found.insert(input.to_owned());
            }
        }
    }
    found.intersection(&known).cloned().collect()
}

fn write_shapes(action: &Value) -> Vec<WriteShape> {
    let mut writes = BTreeMap::<(String, String), BTreeSet<String>>::new();
    if let Some(function_writes) = action["plan"]["function"]["writes"].as_array() {
        for write in function_writes {
            let Some(record_type) = write["targetRecordType"].as_str() else {
                continue;
            };
            let Some(operation) = write["operation"].as_str() else {
                continue;
            };
            writes
                .entry((record_type.into(), operation.into()))
                .or_default()
                .extend(strings(&write["fields"]));
        }
    }
    if let Some(effects) = action["plan"]["effects"].as_array() {
        for effect in effects {
            let Some(record_type) = effect["target"]["recordType"].as_str() else {
                continue;
            };
            let Some(operation) = effect["operation"].as_str() else {
                continue;
            };
            let fields = effect["mutations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|mutation| mutation["field"].as_str())
                .map(str::to_owned);
            writes
                .entry((record_type.into(), operation.into()))
                .or_default()
                .extend(fields);
        }
    }
    writes
        .into_iter()
        .map(|((record_type, operation), fields)| WriteShape {
            record_type,
            operation,
            fields,
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalRowBoundaries {
    Unrestricted,
    Restricted(BTreeMap<String, Value>),
}

impl CanonicalRowBoundaries {
    fn from_target(target: &Value) -> Self {
        let Some(boundaries) = target["rowBoundaries"].as_array() else {
            return Self::Unrestricted;
        };
        if boundaries.is_empty() {
            return Self::Unrestricted;
        }
        Self::Restricted(
            boundaries
                .iter()
                .map(|boundary| {
                    (
                        serde_json::to_string(boundary).unwrap_or_default(),
                        boundary.clone(),
                    )
                })
                .collect(),
        )
    }

    fn into_authoring_value(self) -> Value {
        match self {
            Self::Unrestricted => Value::String("unrestricted".into()),
            Self::Restricted(boundaries) => Value::Array(boundaries.into_values().collect()),
        }
    }
}

fn action_row_boundaries(
    action: &Value,
    human_permission: Option<&Value>,
    record_type: &str,
) -> Result<Value> {
    let authored_targets = human_permission
        .and_then(|permission| permission["targets"].as_array())
        .into_iter()
        .flatten()
        .filter(|target| target["recordType"].as_str() == Some(record_type))
        .collect::<Vec<_>>();
    let targets = if authored_targets.is_empty() {
        action["permissions"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|permission| permission["targets"].as_array().into_iter().flatten())
            .filter(|target| target["recordType"].as_str() == Some(record_type))
            .collect::<Vec<_>>()
    } else {
        authored_targets
    };
    let mut alternatives = targets
        .iter()
        .map(|target| CanonicalRowBoundaries::from_target(target));
    let inferred = alternatives
        .next()
        .unwrap_or(CanonicalRowBoundaries::Unrestricted);
    if alternatives.any(|candidate| candidate != inferred) {
        return Err(ProviderAddFailure::AmbiguousReviewerBoundaries {
            action_id: action["id"].as_str().unwrap_or_default().into(),
            record_type: record_type.into(),
        }
        .into());
    }
    Ok(inferred.into_authoring_value())
}

fn context_record_reads(
    action: &Value,
    context_fields: &Value,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut reads = BTreeMap::<String, BTreeSet<String>>::new();
    for field in context_fields.as_object().into_iter().flat_map(Map::values) {
        match field["type"].as_str() {
            Some("changes") => {
                let Some(record_type) = field["recordType"].as_str() else {
                    continue;
                };
                reads
                    .entry(record_type.into())
                    .or_default()
                    .extend(strings(&field["fields"]));
            }
            Some("record") => {
                let Some(input) = field["input"].as_str() else {
                    continue;
                };
                let Some(selected) = field["field"].as_str() else {
                    continue;
                };
                let Some(record_type) = action["inputs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|candidate| candidate["id"].as_str() == Some(input))
                    .and_then(|candidate| candidate["fieldType"]["target"].as_str())
                else {
                    continue;
                };
                reads
                    .entry(record_type.into())
                    .or_default()
                    .insert(selected.into());
            }
            _ => {}
        }
    }
    reads
}

fn record_grants_ready(
    access: &Value,
    profile_id: &str,
    required: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    required.iter().all(|(record_type, fields)| {
        access["recordTypes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|record| record["recordType"].as_str() == Some(record_type))
            .and_then(|record| {
                record["profiles"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|profile| profile["id"].as_str() == Some(profile_id))
            })
            .is_some_and(|profile| {
                permission_has(profile, "get")
                    && fields.is_subset(&strings(&profile["readableFields"]))
            })
    })
}

fn occupied_profile_ids(proposals: &Value, actions: &Value, access: &Value) -> BTreeSet<String> {
    let mut occupied = BTreeSet::new();
    occupied.extend(
        access["accessProfiles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|profile| profile["id"].as_str())
            .map(str::to_owned),
    );
    for record in access["recordTypes"].as_array().into_iter().flatten() {
        occupied.extend(
            record["profiles"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|profile| profile["id"].as_str())
                .map(str::to_owned),
        );
    }
    for dataset in access["statisticalDatasets"]
        .as_array()
        .into_iter()
        .flatten()
    {
        occupied.extend(
            dataset["accessProfiles"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|profile| profile["id"].as_str())
                .map(str::to_owned),
        );
        for audience in ["readLive", "publish", "readReleases"] {
            occupied.extend(strings(&dataset[audience]));
        }
    }
    for action in actions["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(proposals["actions"].as_array().into_iter().flatten())
    {
        occupied.extend(
            action["permissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|permission| permission["profileId"].as_str())
                .map(str::to_owned),
        );
        occupied.extend(
            action["execution"]["proposal"]["permissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|permission| permission["profileId"].as_str())
                .map(str::to_owned),
        );
    }
    occupied
}

fn unused_profile_id(
    proposals: &Value,
    actions: &Value,
    access: &Value,
    action_id: &str,
    purpose: &str,
) -> String {
    let occupied = occupied_profile_ids(proposals, actions, access);
    let preferred = local_id(action_id, purpose);
    if !occupied.contains(&preferred) {
        return preferred;
    }
    for sequence in 2_u32.. {
        let candidate = local_id(&preferred, &sequence.to_string());
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("the finite profile set cannot exhaust numeric suffixes")
}

fn service_profile_is_status_only(
    actions: &Value,
    access: &Value,
    action_id: &str,
    authority_id: &str,
    profile_id: &str,
) -> bool {
    let has_record_grant = access["recordTypes"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|record| record["profiles"].as_array().into_iter().flatten())
        .any(|profile| {
            profile["id"].as_str() == Some(profile_id)
                && !strings(&profile["operations"]).is_empty()
        });
    if has_record_grant {
        return false;
    }
    let has_action_grant = actions["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|action| action["permissions"].as_array().into_iter().flatten())
        .any(|permission| permission["profileId"].as_str() == Some(profile_id));
    if has_action_grant {
        return false;
    }
    let has_statistical_grant = access["statisticalDatasets"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|dataset| {
            ["readLive", "publish", "readReleases"]
                .into_iter()
                .any(|audience| strings(&dataset[audience]).contains(profile_id))
        });
    if has_statistical_grant {
        return false;
    }
    actions["actions"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|action| {
            action["execution"]["proposal"]["permissions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |permission| (action, permission))
        })
        .filter(|(_, permission)| permission["profileId"].as_str() == Some(profile_id))
        .all(|(action, permission)| {
            action["id"].as_str() == Some(action_id)
                && permission["actorKind"].as_str() == Some("service")
                && strings(&permission["operations"])
                    == BTreeSet::from(["get-review-status".to_owned()])
                && permission["reviewAuthority"].as_str() == Some(authority_id)
        })
}

fn proposed_context(action: &Value, writes: &[WriteShape]) -> (Value, Vec<String>, Value) {
    let mut fields = Map::new();
    let mut used_names = BTreeSet::new();
    for input in used_inputs(action) {
        let preferred = action["inputs"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|candidate| candidate["id"].as_str() == Some(&input))
            .and_then(|candidate| candidate["apiName"].as_str())
            .map_or_else(|| public_name(&input), str::to_owned);
        let (stem, semantic_suffix) = if preferred == "changes" {
            ("changes", "Input")
        } else {
            (preferred.as_str(), "")
        };
        let name = allocate_context_name(stem, semantic_suffix, &mut used_names);
        fields.insert(name, json!({"type":"input","input":input}));
    }
    let input_only = Value::Object(fields.clone());
    let mut record_types = writes
        .iter()
        .map(|write| write.record_type.clone())
        .collect::<BTreeSet<_>>();
    for record_type in std::mem::take(&mut record_types) {
        let selected = writes
            .iter()
            .filter(|write| write.record_type == record_type)
            .flat_map(|write| write.fields.iter().cloned())
            .collect::<BTreeSet<_>>();
        if selected.is_empty() {
            continue;
        }
        let (stem, semantic_suffix) = if writes
            .iter()
            .map(|write| write.record_type.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == 1
        {
            ("changes".to_owned(), "")
        } else {
            (public_name(&record_type), "Changes")
        };
        let name = allocate_context_name(&stem, semantic_suffix, &mut used_names);
        fields.insert(
            name,
            json!({"type":"changes","recordType":record_type,"fields":selected}),
        );
    }
    let names = fields.keys().cloned().collect();
    (Value::Object(fields), names, input_only)
}

fn ensure_default_context_supported(
    action_id: &str,
    actions: &Value,
    writes: &[WriteShape],
) -> Result<()> {
    for write in writes {
        for field_id in &write.fields {
            let encrypted = actions["recordTypes"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|record| record["id"].as_str() == Some(&write.record_type))
                .and_then(|record| record["fields"].as_array())
                .into_iter()
                .flatten()
                .find(|field| field["id"].as_str() == Some(field_id))
                .and_then(|field| field["encrypted"].as_bool())
                .ok_or(ProviderAddFailure::InvalidReport {
                    command: "Run bregctl --format json explain actions BREG_PROJECT with the matching release and confirm that written fields include boolean encrypted metadata.",
                })?;
            if encrypted {
                return Err(ProviderAddFailure::EncryptedReviewContext {
                    action_id: action_id.into(),
                }
                .into());
            }
        }
    }
    Ok(())
}

fn permission_has(permission: &Value, operation: &str) -> bool {
    permission["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|candidate| candidate.as_str() == Some(operation))
}

fn bypass_paths(access: &Value, writes: &[WriteShape]) -> Vec<ProviderAddBypass> {
    let mut paths = Vec::new();
    for write in writes {
        let Some(record) = access["recordTypes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|record| record["recordType"].as_str() == Some(&write.record_type))
        else {
            continue;
        };
        if record["mutationPolicy"][&write.operation].as_str() == Some("proposal-required") {
            continue;
        }
        for profile in record["profiles"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|profile| permission_has(profile, &write.operation))
        {
            let writable = strings(&profile["writableFields"]);
            let fields = write
                .fields
                .intersection(&writable)
                .cloned()
                .collect::<Vec<_>>();
            if fields.is_empty() {
                continue;
            }
            paths.push(ProviderAddBypass {
                record_type: write.record_type.clone(),
                operation: write.operation.clone(),
                profile: profile["id"].as_str().unwrap_or("unnamed-profile").into(),
                fields,
                mutation_policy: Value::Object(Map::from_iter([(
                    write.operation.clone(),
                    Value::String("proposal-required".into()),
                )])),
            });
        }
    }
    paths
}

fn plan(
    action_id: &str,
    pattern: &str,
    proposals: &Value,
    actions: &Value,
    access: &Value,
) -> Result<AddPlan> {
    let Some(action) = action_by_id(proposals, action_id) else {
        if action_by_id(actions, action_id).is_some() {
            return Err(ProviderAddFailure::WrongMode.into());
        }
        return Err(ProviderAddFailure::UnknownAction.into());
    };
    let proposal = &action["execution"]["proposal"];
    let review = &proposal["review"];
    let source_namespace = review["source"]
        .as_str()
        .or_else(|| actions["registryId"].as_str())
        .unwrap_or("registry")
        .to_owned();
    let policy_selection = if review["policy"].is_null() {
        PolicySelection::current(pattern)
    } else {
        serde_json::from_value::<PolicySelection>(review["policy"].clone())
            .ok()
            .filter(|selection| selection.check().is_ok())
            .ok_or(ProviderAddFailure::InvalidReport {
                command: "Run bregctl --format json explain proposals BREG_PROJECT with the matching release and inspect the Action's policy selection.",
            })?
    };
    let policy_id = policy_selection.id.clone();
    if LocalId::new(policy_id.clone()).is_err() {
        return Err(ProviderAddFailure::PolicyIdUnsupported {
            action_id: action_id.into(),
        }
        .into());
    }
    let authority_id = review["authority"]
        .as_str()
        .unwrap_or("casework")
        .to_owned();
    let writes = write_shapes(action);
    let existing_context = proposal["reviewContext"].as_object();
    if existing_context.is_none() {
        ensure_default_context_supported(action_id, actions, &writes)?;
    }
    let (context, proposed_fields, _) = proposed_context(action, &writes);
    if existing_context.is_none()
        && (proposed_fields.len() > 64
            || context
                .as_object()
                .into_iter()
                .flat_map(|fields| fields.values())
                .any(|field| {
                    field["type"].as_str() == Some("changes")
                        && field["fields"]
                            .as_array()
                            .is_some_and(|fields| fields.len() > 64)
                }))
    {
        return Err(ProviderAddFailure::ReviewContextBounds {
            action_id: action_id.into(),
        }
        .into());
    }
    let effective_context = existing_context
        .and_then(|context| context.get("fields"))
        .cloned()
        .unwrap_or_else(|| context.clone());
    let context_fields = existing_context
        .and_then(|context| context.get("fields"))
        .and_then(Value::as_object)
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_else(|| proposed_fields.clone());
    let required_reads = context_record_reads(action, &effective_context);
    let human_permissions = proposal["permissions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|permission| {
            permission["actorKind"].as_str() == Some("human")
                && !strings(&permission["requesterClients"]).is_empty()
                && permission_has(permission, "get-review-context")
        })
        .collect::<Vec<_>>();
    let complete_human_permission = human_permissions.iter().copied().find(|permission| {
        let readable = strings(&permission["readableContextFields"]);
        context_fields.iter().all(|field| readable.contains(field))
            && permission["profileId"]
                .as_str()
                .is_some_and(|profile| record_grants_ready(access, profile, &required_reads))
    });
    let human_permission = complete_human_permission.or_else(|| human_permissions.first().copied());
    let human_profile = human_permission
        .and_then(|permission| permission["profileId"].as_str())
        .map_or_else(
            || unused_profile_id(proposals, actions, access, action_id, "reviewer"),
            str::to_owned,
        );
    let human_clients = human_permission
        .map(|permission| strings(&permission["requesterClients"]))
        .unwrap_or_else(|| BTreeSet::from([local_id(action_id, "review-ui")]));
    let service_permission = proposal["permissions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|permission| {
            permission["actorKind"].as_str() == Some("service")
                && permission_has(permission, "get-review-status")
                && permission["reviewAuthority"].as_str() == Some(&authority_id)
                && permission["profileId"].as_str().is_some_and(|profile| {
                    service_profile_is_status_only(
                        actions,
                        access,
                        action_id,
                        &authority_id,
                        profile,
                    )
                })
        });
    let service_profile = service_permission
        .and_then(|permission| permission["profileId"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            unused_profile_id(proposals, actions, access, action_id, "review-status")
        });
    let service_scopes = service_permission
        .map(|permission| strings(&permission["requiredScopes"]).into_iter().collect())
        .unwrap_or_else(|| vec!["registry:proposal:review-status".into()]);
    let service_clients = service_permission
        .map(|permission| {
            strings(&permission["requesterClients"])
                .into_iter()
                .collect()
        })
        .filter(|clients: &Vec<String>| !clients.is_empty())
        .unwrap_or_else(|| vec![service_profile.clone()]);
    // BReg requires Proposal authority for every planned and referenced target,
    // even when a reference input is absent from the review context. Ordinary
    // Record reads remain limited to the context's record-backed projections.
    let proposal_targets = writes
        .iter()
        .map(|write| write.record_type.clone())
        .chain(
            action["inputs"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|input| {
                    (input["fieldType"]["type"].as_str() == Some("reference"))
                        .then(|| input["fieldType"]["target"].as_str().map(str::to_owned))
                        .flatten()
                }),
        )
        .chain(required_reads.keys().cloned())
        .collect::<BTreeSet<_>>();
    let reviewer_boundaries = if complete_human_permission.is_none() {
        proposal_targets
            .iter()
            .map(|record_type| {
                action_row_boundaries(action, human_permission, record_type)
                    .map(|boundaries| (record_type.clone(), boundaries))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
    } else {
        BTreeMap::new()
    };
    let mut changes = Vec::new();
    if review["type"].as_str() != Some("required") {
        changes.push(ProviderAddChange {
            path: format!("actions[id={action_id}].execution.proposal.review"),
            explanation: "Requires the selected Casework policy before this Action may be applied; it grants no source write authority.".into(),
            yaml: json!({"actions":[{"id":action_id,"execution":{"mode":"proposal","proposal":{"review":{"type":"required","authority":authority_id,"source":source_namespace,"policy":{"id":policy_id}}}}}]}),
        });
    }
    if existing_context.is_none() {
        changes.push(ProviderAddChange {
            path: format!("actions[id={action_id}].execution.proposal.reviewContext"),
            explanation: "Discloses only plan-used inputs and the before/after values of fields this plan writes.".into(),
            yaml: json!({"actions":[{"id":action_id,"execution":{"mode":"proposal","proposal":{"reviewContext":{"id":local_id(action_id,"review-context"),"fields":context}}}}]}),
        });
    }
    let declared_authority = actions["reviewAuthorities"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|authority| {
            authority["id"].as_str() == Some(&authority_id)
                && authority["protocol"].as_str()
                    == Some("id.registrystack.org/protocols/review/v1")
        });
    if !declared_authority {
        changes.push(ProviderAddChange {
            path: format!("reviewAuthorities[id={authority_id}]"),
            explanation: "Declares the logical Review provider protocol; its endpoint and credential remain deployment configuration.".into(),
            yaml: json!({"reviewAuthorities":[{"id":authority_id,"protocol":"id.registrystack.org/protocols/review/v1"}]}),
        });
    }
    if complete_human_permission.is_none() {
        let targets = proposal_targets
            .into_iter()
            .map(|record_type| {
                let boundaries = reviewer_boundaries
                    .get(&record_type)
                    .expect("every Proposal target has inferred reviewer boundaries");
                json!({"recordType":record_type,"rowBoundaries":boundaries})
            })
            .collect::<Vec<_>>();
        let records = required_reads
            .iter()
            .map(|(record_type, fields)| {
                let boundaries = reviewer_boundaries
                    .get(record_type)
                    .expect("every read record type has inferred reviewer boundaries");
                json!({"recordType":record_type,"operations":["get"],"readableFields":fields,"rowBoundaries":boundaries})
            })
            .collect::<Vec<_>>();
        let required_scopes =
            match human_permission.and_then(|permission| permission["requiredScopes"].as_array()) {
                Some(scopes) if scopes.is_empty() => Value::String("unrestricted".into()),
                Some(scopes) => Value::Array(scopes.clone()),
                None => json!(["registry:proposal:review"]),
            };
        let required_purposes = match human_permission
            .and_then(|permission| permission["requiredPurposes"].as_array())
        {
            Some(purposes) if purposes.is_empty() => None,
            Some(purposes) => Some(Value::Array(purposes.clone())),
            None => Some(json!(["registry-review"])),
        };
        let mut permissions = json!({"proposals":[{
            "action":action_id,
            "operations":["get-review-context"],
            "readableContextFields":context_fields,
            "targets":targets
        }]});
        if !records.is_empty() {
            permissions["records"] = Value::Array(records);
        }
        let mut profile = json!({"id":human_profile,
            "actorKind":"human", "requesterClients":human_clients,
            "principalClaim":human_permission.and_then(|permission|permission["principalClaim"].as_str()).unwrap_or("registry_principal"),
            "requiredScopes":required_scopes,
            "permissions":permissions
        });
        if let Some(required_purposes) = required_purposes {
            profile["requiredPurposes"] = required_purposes;
        }
        changes.push(ProviderAddChange {
            path: format!("accessProfiles[id={human_profile}]"),
            explanation: "Lets a human using the explicitly bound review client read only the named review-context fields and any required current Record fields under the Action's target row boundaries. Bind requesterClients to the intended reviewer UI clients before applying this fragment.".into(),
            yaml: json!({"accessProfiles":[profile]}),
        });
    }
    let service_ready = service_permission.is_some();
    if !service_ready {
        changes.push(ProviderAddChange {
            path: format!("accessProfiles[id={service_profile}]"),
            explanation: "Lets one purpose-specific service client read Review status only for this Review authority.".into(),
            yaml: json!({"accessProfiles":[{"id":service_profile,"actorKind":"service","principalClaim":"registry_principal","requesterClients":service_clients.clone(),"requiredScopes":["registry:proposal:review-status"],"requiredPurposes":["registry-review"],"permissions":{"proposals":[{"action":action_id,"operations":["get-review-status"],"reviewAuthority":authority_id}]}}]}),
        });
    }
    let deployment = vec![
        ProviderAddChange {
            path: format!("BReg runtime config:/reviewAuthorities/{authority_id}"),
            explanation: "Binds the logical Review authority to Casework with secret references only; this is an operator decision and is not read from the BReg project.".into(),
            yaml: json!({"reviewAuthorities":{(authority_id.clone()):{"endpoint":"https://casework.example.test","tokenRef":"secret:file/casework-review-token"}}}),
        },
        ProviderAddChange {
            path: "identity provider".into(),
            explanation: "Creates separate identities for the BReg producer, the Casework status reader, and human reviewers; no credential value is generated or printed.".into(),
            yaml: json!({"producerClient":local_id(action_id,"review-producer"),"statusReaderClients":service_clients,"reviewerClients":human_clients,"reviewers":["human reviewer identities accepted by BReg"]}),
        },
    ];
    let read_grant = (complete_human_permission.is_none() && !required_reads.is_empty()).then(|| {
        let records = required_reads
            .iter()
            .map(|(record_type, selected)| {
                let boundaries = reviewer_boundaries
                    .get(record_type)
                    .expect("every read record type has inferred reviewer boundaries");
                json!({"recordType":record_type,"operations":["get"],"readableFields":selected,"rowBoundaries":boundaries})
            })
            .collect::<Vec<_>>();
        ProviderAddNotice {
            explanation: "Each record or changes projection requires a real records.get grant, limited to the selected fields and the Action's row boundaries; this grant exposes current source data to the reviewer.".into(),
            yaml: json!({"accessProfiles":[{"id":human_profile,"permissions":{"records":records}}]}),
        }
    });
    let input_only = effective_context
        .as_object()
        .into_iter()
        .flat_map(|fields| fields.iter())
        .filter(|(_, field)| field["type"].as_str() == Some("input"))
        .map(|(name, field)| (name.clone(), field.clone()))
        .collect::<Map<_, _>>();
    let effective_context_id = existing_context
        .and_then(|context| context.get("id"))
        .and_then(Value::as_str)
        .map_or_else(|| local_id(action_id, "review-context"), str::to_owned);
    let inputs_only_alternative = (!required_reads.is_empty()).then(|| ProviderAddNotice {
        explanation: "Use this inputs-only context instead when reviewers do not need current Record values; it needs no records.get grant.".into(),
        yaml: json!({"actions":[{"id":action_id,"execution":{"mode":"proposal","proposal":{"reviewContext":{"id":effective_context_id,"fields":input_only}}}}]}),
    });
    Ok(AddPlan {
        action: action.clone(),
        source_namespace,
        policy_id,
        policy_selection,
        authority_id,
        context_fields,
        changes,
        deployment,
        bypass_paths: bypass_paths(access, &writes),
        read_grant,
        inputs_only_alternative,
        service_profile,
        service_scopes,
    })
}

fn report(ok: bool, data: ProviderAddData) -> Result<Value> {
    let mut value = serde_json::to_value(data)?;
    let fields = value
        .as_object_mut()
        .context("provider add data is not an object")?;
    fields.insert("ok".into(), Value::Bool(ok));
    fields.insert("command".into(), Value::String("provider add".into()));
    if !ok {
        fields.insert(
            "diagnostics".into(),
            serde_json::to_value(vec![Diagnostic::error(
                "casework.provider-add.breg-changes-needed",
                "--breg-project",
                "the BReg Action is not ready for the selected Casework approval pattern",
                "Review the proposed least-privilege YAML, apply the intended BReg changes yourself, then run the same provider add command again.",
            )])?,
        );
    }
    Ok(value)
}

fn confirmed(value: Value, step: &'static str) -> Result<Value> {
    if value["ok"] == true {
        Ok(value)
    } else {
        Err(anyhow::anyhow!("{step} did not confirm success"))
    }
}

fn write_yaml(path: &Path, value: &Value) -> Result<()> {
    let header = if path.file_name().and_then(|name| name.to_str()) == Some("casework.yaml") {
        "# yaml-language-server: $schema=.casework/schemas/project.schema.json\n"
    } else if path.file_name().and_then(|name| name.to_str()) == Some("runtime.example.yaml") {
        "# yaml-language-server: $schema=.casework/schemas/runtime.schema.json\n"
    } else {
        ""
    };
    fs::write(path, format!("{header}{}", serde_norway::to_string(value)?))?;
    Ok(())
}

fn configure_project(
    project: &Path,
    final_project: &Path,
    package_output: Option<&Path>,
    pattern: &str,
    plan: &AddPlan,
    export: &BregContextExport,
    schema_path: &Path,
) -> Result<String> {
    let action_id = export.action_id.as_str();
    let provider_id = local_id(action_id, "context");
    let description = format!("context-providers/{provider_id}.json");
    let mut document = crate::templates::approval_project(pattern)?;
    document["project"]["id"] = json!(plan.policy_id);
    let template_policy = document["reviewPolicies"]
        .as_object_mut()
        .and_then(|policies| policies.remove(pattern))
        .context("approval pattern has no matching review policy")?;
    let mut policy = template_policy;
    policy["context"] =
        json!({"mode":"current-source","provider":provider_id,"contract":export.contract});
    policy["displaySchema"] = json!({"$ref":format!("schemas/{action_id}.schema.json")});
    document["reviewPolicies"] = Value::Object(Map::from_iter([(plan.policy_id.clone(), policy)]));
    document["contextProviders"] = Value::Object(Map::from_iter([(
        provider_id.clone(),
        json!({
            "capabilities":["human-display","service-status"],
            "sourceNamespace":plan.source_namespace,
            "deploymentRef":provider_id,
            "description":description,
            "serviceProfiles":{"service-status":plan.service_profile}
        }),
    )]));
    let producer_id = local_id(action_id, "review-producer");
    document["trustedProducers"] = Value::Object(Map::from_iter([(
        producer_id.clone(),
        json!({
            "profile":"requester",
            "issuer":"https://identity.example.test",
            "subject":format!("{producer_id}.example.test"),
            "trustedInitiatorIssuer":"https://identity.example.test",
            "sourceNamespaces":[plan.source_namespace],
            "reviewPolicies":[plan.policy_id],
            "retention":{"receiptRetentionDays":30}
        }),
    )]));
    write_yaml(&project.join("casework.yaml"), &document)?;

    // The pattern starter's submitted-context fixture is intentionally not
    // meaningful after rebinding the policy to an authoritative current source.
    let fixtures = project.join("fixtures");
    if fixtures.exists() {
        fs::remove_dir_all(fixtures)?;
    }

    fs::create_dir_all(project.join("schemas"))?;
    fs::copy(
        schema_path,
        project.join(format!("schemas/{action_id}.schema.json")),
    )?;
    fs::create_dir_all(project.join("context-providers"))?;
    fs::write(
        project.join(&description),
        serde_json::to_vec_pretty(export)?,
    )?;

    let runtime_path = project.join("runtime.example.yaml");
    let runtime_bytes = fs::read(&runtime_path)?;
    let mut runtime = Reader::new(runtime_path.display().to_string())
        .scan(&runtime_bytes)?
        .context("runtime example is empty")?
        .to_json_value();
    runtime["identity"]["databaseId"] = json!(local_id(&plan.policy_id, "casework"));
    let absolute = std::path::absolute(final_project)?;
    let package_root = package_output
        .map(std::path::absolute)
        .transpose()?
        .unwrap_or_else(|| absolute.join(".casework/package"));
    runtime["package"]["root"] = json!(package_root);
    runtime["secretProviders"]["file"]["root"] = json!(absolute.join("secrets"));
    runtime["audit"]["path"] = json!(absolute.join("state/audit.ndjson"));
    let mut provider_runtime = json!({
        "baseUrl":"https://registry.example.test",
        "statusProfile":plan.service_profile,
        "tokenEndpoint":"https://identity.example.test/oauth2/token",
        "clientAssertionAudience":"https://identity.example.test",
        "resource":format!("urn:breg:{}",plan.source_namespace),
        "clientIdRef":format!("secret:file/{}",local_id(action_id,"status-client-id")),
        "clientAssertionKeyRef":format!("secret:file/{}",local_id(action_id,"status-client-key"))
    });
    if !plan.service_scopes.is_empty() {
        provider_runtime["scopes"] = json!(plan.service_scopes);
    }
    runtime["contextProviders"] =
        Value::Object(Map::from_iter([(provider_id.clone(), provider_runtime)]));
    write_yaml(&project.join("runtime.example.yaml"), &runtime)?;
    Ok(provider_id)
}

#[derive(Deserialize)]
struct ComparableReviewStages {
    #[serde(deserialize_with = "typed::unique_id_list")]
    stages: Vec<ReviewStagePolicy>,
}

#[derive(Deserialize)]
struct ComparableReviewOutcomes {
    #[serde(deserialize_with = "typed::id_keyed_or_list")]
    outcomes: Vec<ReviewOutcomePolicy>,
}

fn comparable_review_stages(policy: &Value) -> Option<Vec<ReviewStagePolicy>> {
    serde_json::from_value::<ComparableReviewStages>(policy.clone())
        .ok()
        .map(|policy| policy.stages)
}

fn comparable_review_outcomes(policy: &Value) -> Option<Vec<ReviewOutcomePolicy>> {
    serde_json::from_value::<ComparableReviewOutcomes>(policy.clone())
        .ok()
        .map(|policy| policy.outcomes)
}

fn existing_agreement(
    project: &Path,
    pattern: &str,
    plan: &AddPlan,
    export: &BregContextExport,
) -> Result<String> {
    const PAIR_REMEDY: &str = "Run caseworkctl provider pair --apply when the native context contract changed; provider add never rewrites an existing project.";
    const PATTERN_REMEDY: &str = "Inspect the authored approval pattern at the reported path and reconcile it explicitly; provider add never rewrites an existing project.";
    const RUNTIME_REMEDY: &str = "Update runtime.example.yaml so this provider's status binding names the current BReg status profile and requests every scope that profile requires, then run provider add again. Existing runtime files are never rewritten.";
    let project_path = project.join("casework.yaml");
    let project_bytes = fs::read(&project_path)?;
    let document = Reader::new(project_path.display().to_string())
        .scan(&project_bytes)?
        .context("Casework project is empty")?
        .to_json_value();
    let policy = &document["reviewPolicies"][&plan.policy_id];
    let provider_id = policy["context"]["provider"].as_str().ok_or_else(|| {
        ProviderAddFailure::ExistingMismatch {
            path: format!("/reviewPolicies/{}/context/provider", plan.policy_id),
            remedy: PATTERN_REMEDY,
        }
    })?;
    if policy["context"]["mode"].as_str() != Some("current-source") {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/reviewPolicies/{}/context/mode", plan.policy_id),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    if policy["context"]["contract"] != serde_json::to_value(&export.contract)? {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/reviewPolicies/{}/context/contract", plan.policy_id),
            remedy: PAIR_REMEDY,
        }
        .into());
    }
    if document["contextProviders"][provider_id]["sourceNamespace"].as_str()
        != Some(&plan.source_namespace)
    {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/contextProviders/{provider_id}/sourceNamespace"),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    if document["contextProviders"][provider_id]["serviceProfiles"]["service-status"].as_str()
        != Some(&plan.service_profile)
    {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/contextProviders/{provider_id}/serviceProfiles/service-status"),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    let deployment_ref = document["contextProviders"][provider_id]["deploymentRef"]
        .as_str()
        .ok_or_else(|| ProviderAddFailure::ExistingMismatch {
            path: format!("/contextProviders/{provider_id}/deploymentRef"),
            remedy: PATTERN_REMEDY,
        })?;
    let runtime_path = project.join("runtime.example.yaml");
    if runtime_path.is_file() {
        let runtime_bytes = fs::read(&runtime_path)?;
        let runtime = Reader::new(runtime_path.display().to_string())
            .scan(&runtime_bytes)?
            .ok_or_else(|| ProviderAddFailure::ExistingMismatch {
                path: "runtime.example.yaml".into(),
                remedy: RUNTIME_REMEDY,
            })?
            .to_json_value();
        let binding = &runtime["contextProviders"][deployment_ref];
        if binding["statusProfile"].as_str() != Some(&plan.service_profile) {
            return Err(ProviderAddFailure::ExistingMismatch {
                path: format!(
                    "runtime.example.yaml:/contextProviders/{deployment_ref}/statusProfile"
                ),
                remedy: RUNTIME_REMEDY,
            }
            .into());
        }
        let configured_scopes = strings(&binding["scopes"]);
        let required_scopes = plan.service_scopes.iter().cloned().collect::<BTreeSet<_>>();
        if !required_scopes.is_subset(&configured_scopes) {
            return Err(ProviderAddFailure::ExistingMismatch {
                path: format!("runtime.example.yaml:/contextProviders/{deployment_ref}/scopes"),
                remedy: RUNTIME_REMEDY,
            }
            .into());
        }
    }
    let producer_id = local_id(
        plan.action["id"].as_str().unwrap_or_default(),
        "review-producer",
    );
    let producer = &document["trustedProducers"][&producer_id];
    if !strings(&producer["sourceNamespaces"]).contains(&plan.source_namespace) {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/trustedProducers/{producer_id}/sourceNamespaces"),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    if !strings(&producer["reviewPolicies"]).contains(&plan.policy_id) {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/trustedProducers/{producer_id}/reviewPolicies"),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    if producer["trustedInitiatorIssuer"]
        .as_str()
        .is_none_or(str::is_empty)
    {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/trustedProducers/{producer_id}/trustedInitiatorIssuer"),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    let expected = crate::templates::approval_project(pattern)?;
    let expected_policy = &expected["reviewPolicies"][pattern];
    if comparable_review_stages(policy) != comparable_review_stages(expected_policy) {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/reviewPolicies/{}/stages", plan.policy_id),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    if comparable_review_outcomes(policy) != comparable_review_outcomes(expected_policy) {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/reviewPolicies/{}/outcomes", plan.policy_id),
            remedy: PATTERN_REMEDY,
        }
        .into());
    }
    let description = document["contextProviders"][provider_id]["description"]
        .as_str()
        .ok_or_else(|| ProviderAddFailure::ExistingMismatch {
            path: format!("/contextProviders/{provider_id}/description"),
            remedy: PAIR_REMEDY,
        })?;
    let retained: BregContextExport =
        serde_json::from_slice(&fs::read(project.join(description))?)?;
    if retained.contract != export.contract
        || retained.schema_bytes != export.schema_bytes
        || retained.source_namespace != plan.source_namespace
        || retained.action_id != plan.action["id"].as_str().unwrap_or_default()
    {
        return Err(ProviderAddFailure::ExistingMismatch {
            path: format!("/contextProviders/{provider_id}/description"),
            remedy: PAIR_REMEDY,
        }
        .into());
    }
    Ok(provider_id.to_owned())
}

fn ensure_policy_binding(project: &Path, plan: &AddPlan) -> Result<()> {
    // Loading resolves schema references before the policy closure is hashed.
    let compiled_project = crate::project::load_and_check_policy(project)?;
    let policy = compiled_project
        .review_policies
        .iter()
        .find(|policy| policy.id == plan.policy_id);
    if let Some(policy) = policy {
        if plan
            .policy_selection
            .matches(&policy.compile(&compiled_project)?.binding())
        {
            return Ok(());
        }
    }
    Err(ProviderAddFailure::PolicyBindingMismatch {
        action_id: plan.action["id"].as_str().unwrap_or_default().into(),
    }
    .into())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn add(
    project: &Path,
    breg_project: &Path,
    action: &str,
    pattern: &str,
    breg_package: Option<&Path>,
    package_output: Option<&Path>,
    bregctl: &Path,
) -> Result<Value> {
    bregctl_version(bregctl)?;
    let proposals = explain(bregctl, breg_project, "proposals")?;
    let actions = explain(bregctl, breg_project, "actions")?;
    let access = explain(bregctl, breg_project, "access")?;
    let plan = plan(action, pattern, &proposals, &actions, &access)?;
    let default_provider_id = local_id(action, "context");
    if !plan.changes.is_empty() {
        return report(
            false,
            ProviderAddData {
                project: project.into(),
                action_id: action.into(),
                pattern: pattern.into(),
                outcome: ProviderAddState::ChangesNeeded,
                source_namespace: plan.source_namespace,
                policy_id: plan.policy_id,
                authority_id: plan.authority_id,
                provider_id: default_provider_id,
                context_fields: plan.context_fields,
                changes: plan.changes,
                deployment: plan.deployment,
                bypass_paths: plan.bypass_paths,
                read_grant: plan.read_grant,
                inputs_only_alternative: plan.inputs_only_alternative,
                check: None,
                pairing: None,
                package: None,
                source_writes: false,
                next: "Apply only the BReg authoring and runtime changes you intend, then run this command again.".into(),
            },
        );
    }
    if let Some(package) = breg_package {
        breg_package_agrees_with_project(bregctl, breg_project, package)?;
    }
    let nested_package = package_output
        .map(|output| nested_package_path(project, output))
        .transpose()?
        .flatten();

    let parent = absolute_parent(project, "project destination has no parent")?;
    fs::create_dir_all(&parent)?;
    let generated_stage = tempfile::tempdir_in(&parent)?;
    let generated = generated_stage.path().join("schemas");
    generate_schemas(bregctl, breg_project, &generated)?;
    let (export, schema_path) = generated_export(&generated, action, &plan.source_namespace)?;

    if project.exists() {
        let provider_id = existing_agreement(project, pattern, &plan, &export)?;
        let check = confirmed(
            crate::project::check(project, false, false)?,
            "caseworkctl check",
        )?;
        ensure_policy_binding(project, &plan)?;
        let pairing = breg_package
            .map(|package| {
                crate::provider_pair::compare(project, package, Some(&provider_id), bregctl)
            })
            .transpose()?;
        let mut package = breg_package
            .map(|_| {
                confirmed(
                    crate::project::package_dry_run(project, None)?,
                    "caseworkctl package --dry-run",
                )
            })
            .transpose()?;
        if let Some(output) = package_output {
            if !output.exists() {
                return Err(ProviderAddFailure::ExistingPackageOutputRequested.into());
            }
            let verified = registry_platform_config::verify_package(
                output,
                &registry_casework::package_limits(),
                registry_casework::PACKAGE_COMMAND,
            )
            .map_err(|_| ProviderAddFailure::ExistingPackageOutputMismatch)?;
            let planned_digest = package
                .as_ref()
                .and_then(|report| report["packageDigest"].as_str());
            if planned_digest != Some(verified.digest()) {
                return Err(ProviderAddFailure::ExistingPackageOutputMismatch.into());
            }
            if let Some(report) = package.as_mut() {
                report["output"] = json!(output);
                report["dryRun"] = json!(true);
            }
        }
        return report(
            true,
            ProviderAddData {
                project: project.into(),
                action_id: action.into(),
                pattern: pattern.into(),
                outcome: ProviderAddState::InAgreement,
                source_namespace: plan.source_namespace,
                policy_id: plan.policy_id,
                authority_id: plan.authority_id,
                provider_id,
                context_fields: plan.context_fields,
                changes: Vec::new(),
                deployment: plan.deployment,
                bypass_paths: plan.bypass_paths,
                read_grant: plan.read_grant,
                inputs_only_alternative: plan.inputs_only_alternative,
                check: Some(check),
                pairing,
                package,
                source_writes: false,
                next: "The existing project is in agreement. Replace the .test identities and bind the declared endpoints and secret references before deployment.".into(),
            },
        );
    }

    if package_output.is_some_and(Path::exists) {
        return Err(ProviderAddFailure::PackageDestinationExists.into());
    }
    let stage = tempfile::tempdir_in(&parent)?;
    let staged_project = stage.path().join("project");
    crate::project::init(&staged_project, pattern)?;
    let provider_id = configure_project(
        &staged_project,
        project,
        package_output,
        pattern,
        &plan,
        &export,
        &schema_path,
    )?;
    let mut check = confirmed(
        crate::project::check(&staged_project, false, false)?,
        "caseworkctl check",
    )?;
    check = confirmed(
        crate::project::check_runtime_config(
            &staged_project,
            &staged_project.join("runtime.example.yaml"),
            false,
            false,
            Ok(check),
        )?,
        "caseworkctl check --runtime-config",
    )?;
    let pairing = if let Some(package) = breg_package {
        let paired = crate::provider_pair::pair(
            &staged_project,
            &provider_id,
            package,
            action,
            bregctl,
            true,
        )?;
        check = confirmed(
            crate::project::check(&staged_project, false, false)?,
            "caseworkctl check",
        )?;
        crate::provider_pair::compare(&staged_project, package, Some(&provider_id), bregctl)?;
        Some(paired)
    } else {
        None
    };
    ensure_policy_binding(&staged_project, &plan)?;

    let mut package = None;
    let mut external_package = None;
    if breg_package.is_some() {
        if let Some(output) = package_output {
            if let Some(relative) = nested_package.as_deref() {
                let staged = staged_project.join(relative);
                if let Some(parent) = staged.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut report = confirmed(
                    crate::project::package(&staged_project, &staged, None)?,
                    "caseworkctl package",
                )?;
                report["output"] = json!(output);
                package = Some(report);
            } else {
                let output_parent = absolute_parent(output, "package destination has no parent")?;
                fs::create_dir_all(&output_parent)?;
                let package_stage = tempfile::tempdir_in(&output_parent)?;
                let staged = package_stage.path().join("package");
                let report = confirmed(
                    crate::project::package(&staged_project, &staged, None)?,
                    "caseworkctl package",
                )?;
                external_package = Some((package_stage, staged, output.to_path_buf(), report));
            }
        } else {
            package = Some(confirmed(
                crate::project::package_dry_run(&staged_project, None)?,
                "caseworkctl package --dry-run",
            )?);
        }
    }
    fs::rename(&staged_project, project)?;
    if let Some((package_stage, staged, output, mut report)) = external_package {
        if let Err(error) = fs::rename(&staged, &output) {
            let _ = fs::remove_dir_all(project);
            return Err(error.into());
        }
        report["output"] = json!(output);
        drop(package_stage);
        package = Some(report);
    }
    check["project"] = json!(project);
    if check.get("runtimeConfig").is_some() {
        check["runtimeConfig"] = json!(project.join("runtime.example.yaml"));
    }
    report(
        true,
        ProviderAddData {
            project: project.into(),
            action_id: action.into(),
            pattern: pattern.into(),
            outcome: ProviderAddState::Created,
            source_namespace: plan.source_namespace,
            policy_id: plan.policy_id,
            authority_id: plan.authority_id,
            provider_id,
            context_fields: plan.context_fields,
            changes: Vec::new(),
            deployment: plan.deployment,
            bypass_paths: plan.bypass_paths,
            read_grant: plan.read_grant,
            inputs_only_alternative: plan.inputs_only_alternative,
            check: Some(check),
            pairing,
            package,
            source_writes: false,
            next: if breg_package.is_some() {
                "Replace the .test identities and bind the declared endpoints and secret references before deployment."
            } else {
                "Create a sealed BReg package, then run provider add again with --breg-package to verify the native export and dry-run the Casework package."
            }
            .into(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn fake_bregctl(
        root: &Path,
        proposals: &Value,
        actions: &Value,
        access: &Value,
        generate_ok: bool,
        package: Option<(&str, &str)>,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        for (name, explanation) in [
            ("proposals", proposals),
            ("actions", actions),
            ("access", access),
        ] {
            fs::write(
                root.join(format!("{name}.json")),
                serde_json::to_vec(&json!({"ok":true,"explanation":explanation})).unwrap(),
            )
            .unwrap();
        }
        let schema_bytes = include_bytes!(
            "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
        );
        let schema: Value = serde_json::from_slice(schema_bytes).unwrap();
        fs::write(root.join("schema.json"), schema_bytes).unwrap();
        fs::write(
            root.join("index.json"),
            serde_json::to_vec(&json!({"correct-address":{
                "id":schema["$id"],
                "revision":schema["x-registry-definition-revision"],
                "digest":registry_platform_config::sha256_uri(schema_bytes),
                "path":"generated/review-context-schemas/correct-address.schema.json"
            }}))
            .unwrap(),
        )
        .unwrap();
        let executable = root.join("bregctl");
        let generate = if generate_ok {
            format!(
                "mkdir -p \"$output/generated/review-context-schemas\"\ncp '{}' \"$output/generated/review-context-schemas/index.json\"\ncp '{}' \"$output/generated/review-context-schemas/correct-address.schema.json\"\nprintf '%s\\n' '{{\"ok\":true}}'\n",
                root.join("index.json").display(),
                root.join("schema.json").display()
            )
        } else {
            "exit 1\n".into()
        };
        let package_commands = package.map_or_else(String::new, |(digest, registry_revision)| {
            format!(
                concat!(
                    "if [ \"$3\" = \"diff\" ] && [ \"$5\" = \"--package\" ]; then\n",
                    "  printf '%s\\n' '{{\"ok\":true,\"command\":\"diff\",\"profile\":\"authoring\",\"baselineAssurance\":\"integrity-only\",\"findings\":[],\"baselinePackageRevision\":\"{digest}\",\"baselineRegistryRevision\":\"{registry_revision}\",\"candidateRegistryRevision\":\"sha256:{}\",\"changes\":[]}}'\n",
                    "  exit 0\n",
                    "fi\n",
                    "if [ \"$3\" = \"check\" ] && [ \"$4\" = \"--package\" ]; then\n",
                    "  printf '%s\\n' '{{\"ok\":true,\"packageDigest\":\"{digest}\",\"registryRevision\":\"{registry_revision}\"}}'\n",
                    "  exit 0\n",
                    "fi\n"
                ),
                "0".repeat(64),
                digest = digest,
                registry_revision = registry_revision,
            )
        });
        fs::write(
            &executable,
            format!(
                r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '%s\n' 'bregctl {}'
  exit 0
fi
if [ "$3" = "explain" ]; then
  case "$4" in
    proposals) exec cat '{}/proposals.json' ;;
    actions) exec cat '{}/actions.json' ;;
    access) exec cat '{}/access.json' ;;
  esac
fi
{package_commands}
if [ "$3" = "generate" ] && [ "$4" = "schemas" ]; then
  while [ "$1" != "--output" ]; do shift; done
  shift
  output=$1
  {generate}
  exit 0
fi
exit 1
"#,
                registry_platform_buildinfo::DISPLAY_VERSION,
                root.display(),
                root.display(),
                root.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        executable
    }

    fn native_package(root: &Path, mismatched: bool) -> (PathBuf, String) {
        use registry_platform_config::{sha256_uri, write_sum_file, PackageLimits};

        let package = root.join(if mismatched {
            "mismatched-native-package"
        } else {
            "native-package"
        });
        let relative = "generated/review-context-schemas/correct-address.schema.json";
        fs::create_dir_all(package.join("generated/review-context-schemas")).unwrap();
        let original = include_bytes!(
            "../../../products/casework/examples/canonical-review/schemas/correct-address.schema.json"
        );
        let mut schema: Value = serde_json::from_slice(original).unwrap();
        if mismatched {
            schema["x-registry-definition-revision"] = json!(format!("sha256:{}", "a".repeat(64)));
        }
        let schema_bytes = if mismatched {
            serde_json::to_vec_pretty(&schema).unwrap()
        } else {
            original.to_vec()
        };
        fs::write(package.join(relative), &schema_bytes).unwrap();
        fs::write(
            package.join("generated/review-context-schemas/index.json"),
            serde_json::to_vec(&json!({"correct-address":{
                "id":schema["$id"],
                "revision":schema["x-registry-definition-revision"],
                "digest":sha256_uri(&schema_bytes),
                "path":relative
            }}))
            .unwrap(),
        )
        .unwrap();
        let sealed =
            write_sum_file(&package, None, &PackageLimits::default(), "bregctl package").unwrap();
        let digest = sealed.digest().to_owned();
        (package, digest)
    }

    fn facility_explanations() -> (Value, Value, Value) {
        let mut explanations: (Value, Value, Value) = (
            serde_json::from_str(include_str!(
                "../../../products/breg/examples/formats/explain/proposals-explanation.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../products/breg/examples/formats/explain/actions-explanation.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!(
                "../../../products/breg/examples/formats/explain/access-explanation.json"
            ))
            .unwrap(),
        );
        for explanation in [&mut explanations.0, &mut explanations.1] {
            for action in explanation["actions"].as_array_mut().unwrap() {
                for permission in action["execution"]["proposal"]["permissions"]
                    .as_array_mut()
                    .into_iter()
                    .flatten()
                {
                    if permission["profileId"] == "proposal-reviewer" {
                        permission["actorKind"] = json!("human");
                        permission["requesterClients"] = json!(["review-ui"]);
                    }
                }
            }
        }
        explanations
    }

    fn action(review: Value, context: Value, permissions: Value) -> Value {
        json!({
            "id":"correct-address",
            "inputs":[{"id":"facility"},{"id":"address-line"}],
            "plan":{"type":"fixed","effects":[{"operation":"patch","target":{"recordType":"facility","binding":{"kind":"existing","input":"facility"}},"mutations":[{"field":"address-line","kind":"set","value":{"kind":"from-input","input":"address-line"}}]}]},
            "permissions":[{"profileId":"author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}],
            "execution":{"mode":"proposal","proposal":{"review":review,"reviewContext":context,"permissions":permissions}}
        })
    }

    fn explanations(action: Value, authorities: Value) -> (Value, Value, Value) {
        let proposals = json!({"actions":[action.clone()]});
        let actions = json!({"registryId":"facility-registry","reviewAuthorities":authorities,"actions":[action],"recordTypes":[{"id":"facility","fields":[{"id":"address-line","encrypted":false}]}]});
        let access = json!({"recordTypes":[{"recordType":"facility","mutationPolicy":{},"profiles":[{"id":"direct-editor","operations":["patch"],"writableFields":["address-line","name"]}]}]});
        (proposals, actions, access)
    }

    #[test]
    fn used_inputs_follows_typed_references_and_leaves_literal_json_opaque() {
        let declared = json!([
            {"id":"target"}, {"id":"replacement"}, {"id":"expected"},
            {"id":"guard-target"}, {"id":"unused-literal"}
        ]);
        let guards = json!([
            {"input":"guard-target", "equalsInput":"expected"},
            {"input":"unknown"}
        ]);
        let fixed = json!({
            "inputs":declared,
            "commitGuards":guards,
            "plan":{"type":"fixed","effects":[{
                "target":{"binding":{"kind":"existing","input":"target"}},
                "mutations":[
                    {"value":{"kind":"from-input","input":"replacement"}},
                    {"value":{"kind":"literal","value":{"input":"unused-literal"}}}
                ]
            }]}
        });
        assert_eq!(
            used_inputs(&fixed),
            ["expected", "guard-target", "replacement", "target"]
        );
        let function = json!({
            "inputs":declared,
            "commitGuards":guards,
            "plan":{"type":"function","function":{
                "boundInputs":["target","replacement","unknown"],
                "display":{"input":"unused-literal"}
            }}
        });
        assert_eq!(used_inputs(&function), used_inputs(&fixed));
    }

    #[test]
    fn package_containment_uses_one_absolute_lexical_coordinate_system() {
        let relative_project = Path::new("mixed-path-review");
        let absolute_project = std::path::absolute(relative_project).unwrap();
        let relative_output = relative_project.join("build/sealed-casework");
        let absolute_output = absolute_project.join("build/sealed-casework");
        let expected = PathBuf::from("build/sealed-casework");

        assert_eq!(
            nested_package_path(relative_project, &absolute_output).unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            nested_package_path(&absolute_project, &relative_output).unwrap(),
            Some(expected)
        );
        assert!(absolute_parent(
            Path::new("ordinary-relative-project"),
            "project destination has no parent"
        )
        .unwrap()
        .is_absolute());

        let error = nested_package_path(relative_project, &absolute_project).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::PackageDestinationIsProject)
        ));
        let error = nested_package_path(
            relative_project,
            &relative_project.join("../separate-package"),
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::PackageDestinationTraversesProject)
        ));
    }

    #[test]
    fn breg_package_diff_report_requires_valid_registry_revision_bindings() {
        let revision = format!("sha256:{}", "0".repeat(64));
        let valid = json!({
            "apiVersion":"id.registrystack.org/formats/breg/ctl-report/v1alpha1",
            "kind":"BRegCtlReport",
            "ok":true,
            "command":"diff",
            "profile":"authoring",
            "baselineAssurance":"integrity-only",
            "findings":[],
            "baselinePackageRevision":revision,
            "baselineRegistryRevision":revision,
            "candidateRegistryRevision":revision,
            "changes":[]
        });
        let decoded =
            decode_breg_package_diff_report(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(
            decoded.baseline_registry_revision,
            decoded.candidate_registry_revision
        );

        for field in ["baselineRegistryRevision", "candidateRegistryRevision"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(matches!(
                decode_breg_package_diff_report(&serde_json::to_vec(&missing).unwrap()),
                Err(ProviderAddFailure::InvalidReport { .. })
            ));
            for invalid in [Value::Null, json!(""), json!("not-a-digest")] {
                let mut malformed = valid.clone();
                malformed[field] = invalid;
                assert!(matches!(
                    decode_breg_package_diff_report(&serde_json::to_vec(&malformed).unwrap()),
                    Err(ProviderAddFailure::InvalidReport { .. })
                ));
            }
        }

        let mut wrong_command = valid;
        wrong_command["command"] = json!("check");
        assert!(matches!(
            decode_breg_package_diff_report(&serde_json::to_vec(&wrong_command).unwrap()),
            Err(ProviderAddFailure::InvalidReport { .. })
        ));
    }

    #[test]
    fn proposed_context_allocates_collision_free_bounded_names() {
        let long_record_prefix = "a".repeat(56);
        let first_long_record = format!("{long_record_prefix}-record");
        let second_long_record = format!("{long_record_prefix}_record");
        let action = json!({
            "inputs":[
                {"id":"address-line","apiName":"addressLine"},
                {"id":"first-change","apiName":"changesInput"},
                {"id":"second-change","apiName":"changes"},
                {"id":"generated-collision","apiName":"permitRecordChanges"}
            ],
            "plan":{"function":{"boundInputs":[
                "address-line",
                "first-change",
                "generated-collision",
                "second-change"
            ]}}
        });
        let writes = vec![
            WriteShape {
                record_type: "permit-record".into(),
                operation: "patch".into(),
                fields: BTreeSet::from(["status".into()]),
            },
            WriteShape {
                record_type: "permit_record".into(),
                operation: "patch".into(),
                fields: BTreeSet::from(["status".into()]),
            },
            WriteShape {
                record_type: first_long_record.clone(),
                operation: "patch".into(),
                fields: BTreeSet::from(["status".into()]),
            },
            WriteShape {
                record_type: second_long_record.clone(),
                operation: "patch".into(),
                fields: BTreeSet::from(["status".into()]),
            },
        ];

        let (context, names, input_only) = proposed_context(&action, &writes);
        let repeated = proposed_context(&action, &writes);
        assert_eq!(
            (context.clone(), names.clone(), input_only.clone()),
            repeated
        );
        assert_eq!(context.as_object().unwrap().len(), 8, "{context}");
        assert_eq!(input_only.as_object().unwrap().len(), 4, "{input_only}");
        assert_eq!(context["addressLine"]["input"], "address-line");
        assert_eq!(context["changesInput"]["input"], "first-change");
        let retained_inputs = context
            .as_object()
            .unwrap()
            .values()
            .filter(|field| field["type"] == "input")
            .filter_map(|field| field["input"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            retained_inputs,
            BTreeSet::from([
                "address-line",
                "first-change",
                "generated-collision",
                "second-change"
            ])
        );
        let retained_changes = context
            .as_object()
            .unwrap()
            .values()
            .filter(|field| field["type"] == "changes")
            .filter_map(|field| field["recordType"].as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            retained_changes,
            BTreeSet::from([
                first_long_record.as_str(),
                second_long_record.as_str(),
                "permit-record",
                "permit_record"
            ])
        );
        let long_change_names = context
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, field)| {
                matches!(
                    field["recordType"].as_str(),
                    Some(record_type)
                        if record_type == first_long_record || record_type == second_long_record
                )
            })
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert!(
            long_change_names
                .iter()
                .all(|name| name.ends_with("Changes") || name.ends_with("Changes2")),
            "{long_change_names:?}"
        );
        assert!(names.iter().all(|name| {
            name.len() <= 64
                && name
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
                && !matches!(
                    name.as_str(),
                    "id" | "recordId" | "revision" | "createdAt" | "updatedAt" | "deletedAt"
                )
        }));
    }

    #[test]
    fn reviewer_boundary_inference_refuses_different_alternatives() {
        let mut proposed = action(Value::Null, Value::Null, json!([]));
        proposed["permissions"] = json!([
            {"profileId":"north-author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]},
            {"profileId":"owner-author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"owner","claim":"sub","operator":"equals"}]}]}
        ]);
        let (proposals, actions, access) = explanations(proposed, json!([]));

        let error = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap_err();
        assert!(error.to_string().contains("explicit"), "{error:#}");
    }

    #[test]
    fn reviewer_boundary_inference_refuses_unrestricted_and_restricted_alternatives() {
        let mut proposed = action(Value::Null, Value::Null, json!([]));
        proposed["permissions"] = json!([
            {"profileId":"all-authors","targets":[{"recordType":"facility","rowBoundaries":[]}]},
            {"profileId":"north-author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]}
        ]);
        let (proposals, actions, access) = explanations(proposed, json!([]));

        let error = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap_err();
        assert!(error.to_string().contains("explicit"), "{error:#}");
    }

    #[test]
    fn reviewer_boundary_inference_accepts_equal_reordered_sets_once() {
        let jurisdiction =
            json!({"field":"jurisdiction","claim":"jurisdiction","operator":"equals"});
        let owner = json!({"field":"owner","claim":"sub","operator":"equals"});
        let mut proposed = action(Value::Null, Value::Null, json!([]));
        proposed["permissions"] = json!([
            {"profileId":"first-author","targets":[{"recordType":"facility","rowBoundaries":[jurisdiction.clone(),owner.clone(),jurisdiction.clone()]}]},
            {"profileId":"second-author","targets":[{"recordType":"facility","rowBoundaries":[owner.clone(),jurisdiction.clone()]}]}
        ]);
        let (proposals, actions, access) = explanations(proposed, json!([]));

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        let reviewer = planned
            .changes
            .iter()
            .find(|change| change.path.starts_with("accessProfiles[id="))
            .unwrap();
        let expected = json!([jurisdiction, owner]);
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"],
            expected
        );
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["proposals"][0]["targets"][0]
                ["rowBoundaries"],
            expected
        );
        assert_eq!(
            planned.read_grant.as_ref().unwrap().yaml["accessProfiles"][0]["permissions"]
                ["records"][0]["rowBoundaries"],
            expected
        );
    }

    #[test]
    fn reviewer_boundary_inference_serializes_unrestricted_sentinel() {
        let mut proposed = action(Value::Null, Value::Null, json!([]));
        proposed["permissions"] = json!([
            {"profileId":"all-authors","targets":[{"recordType":"facility","rowBoundaries":[]}]}
        ]);
        let (proposals, actions, access) = explanations(proposed, json!([]));

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        let reviewer = planned
            .changes
            .iter()
            .find(|change| change.path.starts_with("accessProfiles[id="))
            .unwrap();
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"],
            "unrestricted"
        );
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["proposals"][0]["targets"][0]
                ["rowBoundaries"],
            "unrestricted"
        );
        assert_eq!(
            planned.read_grant.as_ref().unwrap().yaml["accessProfiles"][0]["permissions"]
                ["records"][0]["rowBoundaries"],
            "unrestricted"
        );
    }

    #[test]
    fn ready_reviewer_does_not_infer_or_suggest_alternative_boundaries() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"status-reader","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework"}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let mut proposed = action(review, context, permissions);
        proposed["permissions"] = json!([
            {"profileId":"north-author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}]}]},
            {"profileId":"owner-author","targets":[{"recordType":"facility","rowBoundaries":[{"field":"owner","claim":"sub","operator":"equals"}]}]}
        ]);
        let (proposals, actions, mut access) = explanations(
            proposed,
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"human-reviewer","operations":["get"],"readableFields":["address-line"],"rowBoundaries":[{"field":"review-team","claim":"team","operator":"equals"}]}));

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert!(planned.changes.is_empty(), "{:#?}", planned.changes);
        assert!(planned.read_grant.is_none());
    }

    #[test]
    fn incomplete_human_permission_preserves_identity_unrestricted_scope_and_optional_purpose() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui","review-mobile"],"principalClaim":"human_subject","operations":["get-review-context"],"readableContextFields":["facilityId"],"requiredScopes":[],"requiredPurposes":[],"targets":[{"recordType":"facility","rowBoundaries":[]}]}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        let reviewer = &planned
            .changes
            .iter()
            .find(|change| change.path == "accessProfiles[id=human-reviewer]")
            .unwrap()
            .yaml["accessProfiles"][0];
        assert_eq!(reviewer["requiredScopes"], "unrestricted");
        assert_eq!(reviewer["actorKind"], "human");
        assert_eq!(reviewer["principalClaim"], "human_subject");
        assert_eq!(
            reviewer["requesterClients"],
            json!(["review-mobile", "review-ui"])
        );
        assert!(reviewer.get("requiredPurposes").is_none(), "{reviewer}");
        assert_eq!(
            reviewer["permissions"]["records"][0]["rowBoundaries"],
            "unrestricted"
        );
        assert_eq!(
            reviewer["permissions"]["proposals"][0]["targets"][0]["rowBoundaries"],
            "unrestricted"
        );
    }

    #[test]
    fn inputs_only_context_omits_empty_record_permissions() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":[],"targets":[{"recordType":"facility","rowBoundaries":[]}]}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        let reviewer = &planned
            .changes
            .iter()
            .find(|change| change.path == "accessProfiles[id=human-reviewer]")
            .unwrap()
            .yaml["accessProfiles"][0];
        assert!(
            reviewer["permissions"].get("records").is_none(),
            "{reviewer}"
        );
        assert_eq!(
            reviewer["permissions"]["proposals"][0]["readableContextFields"],
            json!(["facilityId"])
        );
        assert!(planned.read_grant.is_none());
        assert!(planned.inputs_only_alternative.is_none());
    }

    #[test]
    fn planner_proposes_only_missing_review_pieces_and_names_direct_bypass() {
        let (proposals, actions, access) =
            explanations(action(Value::Null, Value::Null, json!([])), json!([]));
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        let paths = planned
            .changes
            .iter()
            .map(|change| change.path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.iter().any(|path| path.ends_with(".review")));
        assert!(paths.iter().any(|path| path.ends_with(".reviewContext")));
        assert!(paths
            .iter()
            .any(|path| path.starts_with("reviewAuthorities")));
        assert_eq!(
            planned.context_fields,
            ["addressLine", "changes", "facility"]
        );
        assert_eq!(planned.bypass_paths.len(), 1);
        assert_eq!(planned.bypass_paths[0].fields, ["address-line"]);
        assert_eq!(
            planned.bypass_paths[0].mutation_policy,
            json!({"patch":"proposal-required"})
        );
        assert!(planned.read_grant.is_some());
        assert!(planned.inputs_only_alternative.is_some());
        let reviewer = planned
            .changes
            .iter()
            .find(|change| change.path.starts_with("accessProfiles[id="))
            .unwrap();
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"][0]
                ["field"],
            "jurisdiction"
        );
        assert_eq!(
            reviewer.yaml["accessProfiles"][0]["permissions"]["proposals"][0]["targets"][0]
                ["rowBoundaries"][0]["field"],
            "jurisdiction"
        );
        let rendered = serde_json::to_string(&planned.changes).unwrap();
        assert!(!rendered.contains("supporting-document"));
        assert!(!rendered.contains("tokenValue"));
    }

    #[test]
    fn only_client_bound_human_permissions_are_reused_for_review() {
        for (kind, clients) in [
            (Value::Null, json!([])),
            (json!("human"), json!([])),
            (json!("service"), json!(["review-ui"])),
        ] {
            let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"}}});
            let permissions = json!([{
                "profileId":"existing-reader", "actorKind":kind,
                "requesterClients":clients, "operations":["get-review-context"],
                "readableContextFields":["facilityId"]
            }]);
            let (proposals, actions, access) =
                explanations(action(Value::Null, context, permissions), json!([]));
            let planned = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap();
            let reviewer = planned
                .changes
                .iter()
                .flat_map(|change| {
                    change.yaml["accessProfiles"]
                        .as_array()
                        .into_iter()
                        .flatten()
                })
                .find(|profile| profile["actorKind"] == "human")
                .unwrap();
            assert_ne!(reviewer["id"], "existing-reader");
            assert_eq!(
                reviewer["requesterClients"],
                json!(["correct-address-review-ui"])
            );
            assert!(planned
                .changes
                .iter()
                .all(|change| change.path != "accessProfiles[id=existing-reader]"));
        }
    }

    #[test]
    fn default_context_refuses_encrypted_writes_without_changing_authored_context() {
        for mixed in [false, true] {
            let mut proposed = action(Value::Null, Value::Null, json!([]));
            if mixed {
                proposed["plan"]["effects"][0]["mutations"].as_array_mut().unwrap()
                    .push(json!({"field":"name","kind":"set","value":{"kind":"literal","value":"replacement"}}));
            }
            let (mut proposals, mut actions, access) = explanations(proposed, json!([]));
            actions["recordTypes"][0]["fields"] = json!([
                {"id":"address-line","encrypted":true},
                {"id":"name","encrypted":false}
            ]);
            let error = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ProviderAddFailure>(),
                Some(ProviderAddFailure::EncryptedReviewContext { .. })
            ));
            proposals["actions"][0]["execution"]["proposal"]["reviewContext"] = json!({
                "id":"authored-context", "fields":{"addressLine":{"type":"input","input":"address-line"}}
            });
            let planned = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap();
            assert_eq!(planned.context_fields, ["addressLine"]);
            assert!(planned
                .changes
                .iter()
                .all(|change| !change.path.ends_with(".reviewContext")));
            assert!(planned.read_grant.is_none());
        }
    }

    #[test]
    fn default_context_requires_valid_encryption_metadata_for_written_fields() {
        for metadata in [Value::Null, json!("false"), json!(0)] {
            let (proposals, mut actions, access) =
                explanations(action(Value::Null, Value::Null, json!([])), json!([]));
            actions["recordTypes"][0]["fields"][0]["encrypted"] = metadata;
            let error = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap_err();
            assert!(matches!(
                error.downcast_ref::<ProviderAddFailure>(),
                Some(ProviderAddFailure::InvalidReport { .. })
            ));
        }
    }

    #[test]
    fn complete_existing_review_is_ready_and_preserves_its_names() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"status-reader","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"existing-authority"}
        ]);
        let review = json!({"type":"required","authority":"existing-authority","source":"existing-source","policy":{"id":"existing-policy"}});
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"existing-authority","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"human-reviewer","operations":["get"],"readableFields":["address-line"]}));
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert!(planned.changes.is_empty());
        assert_eq!(planned.source_namespace, "existing-source");
        assert_eq!(planned.policy_id, "existing-policy");
        assert_eq!(planned.authority_id, "existing-authority");
        assert_eq!(planned.service_profile, "status-reader");
    }

    #[test]
    fn readiness_requires_one_human_profile_to_hold_context_and_record_grants() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let permissions = json!([
            {"profileId":"service-context","actorKind":"service","operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"context-only","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"record-only","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId"]},
            {"profileId":"status-reader","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework"}
        ]);
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"id":"record-only","operations":["get"],"readableFields":["address-line"]}),
            );

        let split = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert!(
            split
                .changes
                .iter()
                .any(|change| change.path == "accessProfiles[id=context-only]"),
            "{:#?}",
            split.changes
        );

        let mut complete = proposals;
        complete["actions"][0]["execution"]["proposal"]["permissions"][2]
            ["readableContextFields"] = json!(["facilityId", "changes"]);
        assert!(plan(
            "correct-address",
            "single-reviewer-approval",
            &complete,
            &actions,
            &access,
        )
        .unwrap()
        .changes
        .is_empty());
    }

    #[test]
    fn status_reader_profile_must_not_also_hold_record_authority() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"overprivileged-status","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework","requesterClients":["existing-client"]}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({"id":"human-reviewer","operations":["get"],"readableFields":["address-line"]}),
                json!({"id":"overprivileged-status","operations":["get"],"readableFields":["address-line"]}),
            ]);
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert_eq!(planned.service_profile, "correct-address-review-status");
        assert!(planned.changes.iter().any(|change| {
            change.path == "accessProfiles[id=correct-address-review-status]"
                && change.yaml["accessProfiles"][0]["requesterClients"]
                    == json!(["correct-address-review-status"])
        }));

        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .retain(|profile| profile["id"] != "overprivileged-status");
        let mut action_grant = actions;
        action_grant["actions"][0]["permissions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"profileId":"overprivileged-status","targets":[{"recordType":"facility","rowBoundaries":[]}]}));
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &action_grant,
            &access,
        )
        .unwrap();
        assert_eq!(planned.service_profile, "correct-address-review-status");
    }

    #[test]
    fn status_reader_profile_must_not_hold_statistical_dataset_authority() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"statistics-reader","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework"}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"human-reviewer","operations":["get"],"readableFields":["address-line"]}));

        for audience in ["readLive", "publish", "readReleases"] {
            let mut access = access.clone();
            access["statisticalDatasets"] = json!([{
                "dataset":"facility-counts",
                "accessProfiles":[{"id":"statistics-reader"}],
                "readLive":[],
                "publish":[],
                "readReleases":[]
            }]);
            access["statisticalDatasets"][0][audience] = json!(["statistics-reader"]);
            let planned = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap();
            assert_eq!(planned.service_profile, "correct-address-review-status");
        }

        let mut metadata_only = access;
        metadata_only["statisticalDatasets"] = json!([{
            "dataset":"facility-counts",
            "accessProfiles":[{"id":"statistics-reader"}],
            "readLive":[],
            "publish":[],
            "readReleases":[]
        }]);
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &metadata_only,
        )
        .unwrap();
        assert_eq!(planned.service_profile, "statistics-reader");
    }

    #[test]
    fn reviewer_fallback_never_reuses_an_occupied_profile() {
        for source in [
            "root",
            "record",
            "dataset-profile",
            "dataset-audience",
            "action",
            "proposal",
        ] {
            let (mut proposals, mut actions, mut access) = facility_explanations();
            proposals["actions"][0]["execution"]["proposal"]["permissions"]
                .as_array_mut()
                .unwrap()
                .retain(|permission| !permission_has(permission, "get-review-context"));
            let occupied = "correct-address-reviewer";
            match source {
                "root" => access["accessProfiles"] = json!([{"id":occupied}]),
                "record" => access["recordTypes"][0]["profiles"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":occupied,"operations":["get"]})),
                "dataset-profile" => {
                    access["statisticalDatasets"] = json!([{
                        "dataset":"counts", "accessProfiles":[{"id":occupied}]
                    }])
                }
                "dataset-audience" => {
                    access["statisticalDatasets"] = json!([{
                        "dataset":"counts", "readLive":[occupied]
                    }])
                }
                "action" => actions["actions"][0]["permissions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"profileId":occupied,"targets":[]})),
                "proposal" => actions["actions"][0]["execution"]["proposal"]["permissions"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"profileId":occupied,"operations":["get"]})),
                _ => unreachable!(),
            }
            let planned = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap();
            let reviewer = planned
                .changes
                .iter()
                .find(|change| change.path == "accessProfiles[id=correct-address-reviewer-2]")
                .unwrap_or_else(|| panic!("{source} profile ID must remain reserved"));
            assert_eq!(
                reviewer.yaml["accessProfiles"][0]["id"],
                "correct-address-reviewer-2"
            );
            assert!(!planned
                .changes
                .iter()
                .any(|change| change.path == "accessProfiles[id=correct-address-reviewer]"));
        }
    }

    #[test]
    fn occupied_status_fallback_id_gets_a_new_purpose_specific_id() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"human-reviewer","actorKind":"human","requesterClients":["review-ui"],"operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"correct-address-review-status","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework"}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({"id":"human-reviewer","operations":["get"],"readableFields":["address-line"]}),
                json!({"id":"correct-address-review-status","operations":["get"],"readableFields":["address-line"]}),
            ]);

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert_eq!(planned.service_profile, "correct-address-review-status-2");
        let status_change = planned
            .changes
            .iter()
            .find(|change| change.path == "accessProfiles[id=correct-address-review-status-2]")
            .unwrap();
        assert_eq!(
            status_change.yaml["accessProfiles"][0]["requesterClients"],
            json!(["correct-address-review-status-2"])
        );
    }

    #[test]
    fn agent_context_permission_does_not_satisfy_human_review_access() {
        let context = json!({"id":"address-context","fields":{"facilityId":{"type":"input","input":"facility"},"changes":{"type":"changes","recordType":"facility","fields":["address-line"]}}});
        let permissions = json!([
            {"profileId":"agent-reader","actorKind":"agent","operations":["get-review-context"],"readableContextFields":["facilityId","changes"]},
            {"profileId":"status-reader","actorKind":"service","operations":["get-review-status"],"reviewAuthority":"casework"}
        ]);
        let review = json!({"type":"required","authority":"casework","source":"facility-registry","policy":{"id":"facility-address-review"}});
        let (proposals, actions, mut access) = explanations(
            action(review, context, permissions),
            json!([{"id":"casework","protocol":"id.registrystack.org/protocols/review/v1"}]),
        );
        access["recordTypes"][0]["profiles"]
            .as_array_mut()
            .unwrap()
            .push(
                json!({"id":"agent-reader","operations":["get"],"readableFields":["address-line"]}),
            );
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert!(planned
            .changes
            .iter()
            .any(|change| change.path == "accessProfiles[id=correct-address-reviewer]"));
    }

    #[test]
    fn planner_refuses_policy_ids_casework_cannot_represent_without_mangling() {
        let (mut proposals, actions, access) = facility_explanations();
        for unsupported in [
            "urn:example:review".to_owned(),
            format!("a{}", "b".repeat(64)),
        ] {
            proposals["actions"][0]["execution"]["proposal"]["review"]["policy"]["id"] =
                json!(&unsupported);
            let error = plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap_err();
            let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
            assert!(matches!(
                failure,
                ProviderAddFailure::PolicyIdUnsupported { .. }
            ));
            assert_eq!(
                failure.diagnostic().1,
                "actions[id=correct-address].execution.proposal.review.policy.id"
            );
        }

        let supported = format!("a{}", "b".repeat(63));
        proposals["actions"][0]["execution"]["proposal"]["review"]["policy"]["id"] =
            json!(supported);
        assert_eq!(
            plan(
                "correct-address",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access,
            )
            .unwrap()
            .policy_id,
            supported
        );
    }

    #[test]
    fn planner_distinguishes_unknown_action_and_wrong_mode() {
        let proposals = json!({"actions":[]});
        let actions = json!({"registryId":"registry","reviewAuthorities":[],"actions":[{"id":"immediate","execution":{"mode":"immediate"}}]});
        let access = json!({"recordTypes":[]});
        assert!(matches!(
            plan(
                "immediate",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access
            )
            .unwrap_err()
            .downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::WrongMode)
        ));
        assert!(matches!(
            plan(
                "absent",
                "single-reviewer-approval",
                &proposals,
                &actions,
                &access
            )
            .unwrap_err()
            .downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::UnknownAction)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fake_bregctl_creates_atomically_and_rerun_is_read_only() {
        let temporary = crate::canonical_tempdir();
        let fake_root = temporary.path().join("fake");
        fs::create_dir(&fake_root).unwrap();
        let (mut proposals, actions, access) = facility_explanations();
        let status = proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|permission| permission["profileId"] == "casework-review-status")
            .unwrap();
        status["requiredScopes"] = json!(["registry:facility:review-status"]);
        let bregctl = fake_bregctl(&fake_root, &proposals, &actions, &access, true, None);
        let project = temporary.path().join("review");
        let breg_project = temporary.path().join("breg-project");
        fs::create_dir(&breg_project).unwrap();

        let created = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap();
        assert_eq!(created["ok"], true, "initial generation");
        assert_eq!(created["outcome"], "created");
        assert!(created.get("state").is_none());
        assert_eq!(created["providerId"], "correct-address-context");
        assert_eq!(created["check"]["project"], json!(project));
        assert_eq!(
            created["check"]["runtimeConfig"],
            json!(project.join("runtime.example.yaml"))
        );
        assert!(project.join("casework.yaml").is_file());
        assert!(!project.join("fixtures").exists());
        let runtime_path = project.join("runtime.example.yaml");
        let runtime_bytes = fs::read(&runtime_path).unwrap();
        let runtime = Reader::new(runtime_path.display().to_string())
            .scan(&runtime_bytes)
            .unwrap()
            .unwrap()
            .to_json_value();
        assert_eq!(
            runtime["contextProviders"]["correct-address-context"]["scopes"],
            json!(["registry:facility:review-status"])
        );
        assert_eq!(
            runtime["package"]["root"],
            json!(std::path::absolute(&project)
                .unwrap()
                .join(".casework/package"))
        );
        let authored = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        assert_eq!(
            authored["contextProviders"]["correct-address-context"]["sourceNamespace"],
            "facility-registry"
        );
        assert_eq!(
            authored["contextProviders"]["correct-address-context"]["deploymentRef"],
            "correct-address-context"
        );
        assert_eq!(
            authored["trustedProducers"]["correct-address-review-producer"]["sourceNamespaces"],
            json!(["facility-registry"])
        );
        assert!(
            authored["trustedProducers"]["correct-address-review-producer"]["issuer"]
                .as_str()
                .unwrap()
                .ends_with(".test")
        );
        assert!(
            authored["trustedProducers"]["correct-address-review-producer"]["subject"]
                .as_str()
                .unwrap()
                .ends_with(".test")
        );
        let policy_before = fs::read(project.join("casework.yaml")).unwrap();
        let export_before =
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap();

        let rerun = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap();
        assert_eq!(rerun["ok"], true, "unchanged project rerun");
        assert_eq!(rerun["outcome"], "in-agreement");
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            policy_before
        );
        assert_eq!(
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap(),
            export_before
        );

        let mut configured_runtime = Reader::new(runtime_path.display().to_string())
            .scan(&runtime_bytes)
            .unwrap()
            .unwrap()
            .to_json_value();
        configured_runtime["contextProviders"]["correct-address-context"]["scopes"] = json!([
            "registry:facility:review-status",
            "operator-configured-extra"
        ]);
        write_yaml(&runtime_path, &configured_runtime).unwrap();
        let configured_runtime_bytes = fs::read(&runtime_path).unwrap();
        assert_eq!(
            add(
                &project,
                &breg_project,
                "correct-address",
                "single-reviewer-approval",
                None,
                None,
                &bregctl,
            )
            .unwrap()["outcome"],
            "in-agreement",
            "extra operator scopes remain allowed"
        );
        assert_eq!(fs::read(&runtime_path).unwrap(), configured_runtime_bytes);

        let status = proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|permission| permission["profileId"] == "casework-review-status")
            .unwrap();
        status["requiredScopes"] = json!(["registry:facility:review-status-v2"]);
        fs::write(
            fake_root.join("proposals.json"),
            serde_json::to_vec(&json!({"ok":true,"explanation":proposals})).unwrap(),
        )
        .unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<ProviderAddFailure>()
                .unwrap()
                .diagnostic()
                .1,
            "runtime.example.yaml:/contextProviders/correct-address-context/scopes"
        );
        assert_eq!(fs::read(&runtime_path).unwrap(), configured_runtime_bytes);

        configured_runtime["contextProviders"]["correct-address-context"]["scopes"] = json!([
            "operator-configured-extra",
            "registry:facility:review-status-v2"
        ]);
        write_yaml(&runtime_path, &configured_runtime).unwrap();
        let compatible_runtime_bytes = fs::read(&runtime_path).unwrap();
        assert_eq!(
            add(
                &project,
                &breg_project,
                "correct-address",
                "single-reviewer-approval",
                None,
                None,
                &bregctl,
            )
            .unwrap()["outcome"],
            "in-agreement",
            "the current required scope may coexist with operator scopes"
        );
        assert_eq!(fs::read(&runtime_path).unwrap(), compatible_runtime_bytes);

        configured_runtime["contextProviders"]["correct-address-context"]["statusProfile"] =
            json!("stale-status-reader");
        write_yaml(&runtime_path, &configured_runtime).unwrap();
        let stale_profile_bytes = fs::read(&runtime_path).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<ProviderAddFailure>()
                .unwrap()
                .diagnostic()
                .1,
            "runtime.example.yaml:/contextProviders/correct-address-context/statusProfile"
        );
        assert_eq!(fs::read(&runtime_path).unwrap(), stale_profile_bytes);

        let status = proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|permission| permission["profileId"] == "casework-review-status")
            .unwrap();
        status["requiredScopes"] = json!(["registry:facility:review-status"]);
        fs::write(
            fake_root.join("proposals.json"),
            serde_json::to_vec(&json!({"ok":true,"explanation":proposals})).unwrap(),
        )
        .unwrap();
        fs::remove_file(&runtime_path).unwrap();
        assert_eq!(
            add(
                &project,
                &breg_project,
                "correct-address",
                "single-reviewer-approval",
                None,
                None,
                &bregctl,
            )
            .unwrap()["outcome"],
            "in-agreement",
            "provider agreement does not require an optional runtime example"
        );
        fs::write(&runtime_path, &runtime_bytes).unwrap();

        let mut mismatched = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        mismatched["contextProviders"]["correct-address-context"]["serviceProfiles"]
            ["service-status"] = json!("stale-status-reader");
        write_yaml(&project.join("casework.yaml"), &mismatched).unwrap();
        let mismatch_before = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/contextProviders/correct-address-context/serviceProfiles/service-status"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_before
        );
        assert_eq!(
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap(),
            export_before
        );

        fs::write(project.join("casework.yaml"), &policy_before).unwrap();
        let mut mismatched = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        mismatched["reviewPolicies"]["facility-address-review"]["context"]["contract"]
            ["revision"] = json!(format!("sha256:{}", "a".repeat(64)));
        write_yaml(&project.join("casework.yaml"), &mismatched).unwrap();
        let mismatch_before = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/reviewPolicies/facility-address-review/context/contract"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_before
        );
        assert_eq!(
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap(),
            export_before
        );

        fs::write(project.join("casework.yaml"), &policy_before).unwrap();
        let mut mismatched = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        mismatched["reviewPolicies"]["facility-address-review"]["stages"][0]["requiredApprovals"] =
            json!(2);
        write_yaml(&project.join("casework.yaml"), &mismatched).unwrap();
        let mismatch_before = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/reviewPolicies/facility-address-review/stages"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_before
        );
        assert_eq!(
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap(),
            export_before
        );

        fs::write(project.join("casework.yaml"), &policy_before).unwrap();
        let mut mismatched = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        mismatched["trustedProducers"]["correct-address-review-producer"]["sourceNamespaces"] =
            json!(["other-source"]);
        write_yaml(&project.join("casework.yaml"), &mismatched).unwrap();
        let mismatch_before = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/trustedProducers/correct-address-review-producer/sourceNamespaces"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_before
        );
        assert_eq!(
            fs::read(project.join("context-providers/correct-address-context.json")).unwrap(),
            export_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn unrestricted_status_permission_omits_runtime_scopes_and_new_permission_has_default() {
        let temporary = crate::canonical_tempdir();
        let fake_root = temporary.path().join("fake");
        fs::create_dir(&fake_root).unwrap();
        let (mut proposals, actions, access) = facility_explanations();
        let permissions = proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .unwrap();
        let status = permissions
            .iter_mut()
            .find(|permission| permission["profileId"] == "casework-review-status")
            .unwrap();
        status["requiredScopes"] = json!([]);

        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert!(planned.service_scopes.is_empty());
        let bregctl = fake_bregctl(&fake_root, &proposals, &actions, &access, true, None);
        let project = temporary.path().join("review");
        let breg_project = temporary.path().join("breg-project");
        fs::create_dir(&breg_project).unwrap();
        add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap();
        let runtime_path = project.join("runtime.example.yaml");
        let runtime_bytes = fs::read(&runtime_path).unwrap();
        let runtime = Reader::new(runtime_path.display().to_string())
            .scan(&runtime_bytes)
            .unwrap()
            .unwrap()
            .to_json_value();
        assert!(runtime["contextProviders"]["correct-address-context"]
            .get("scopes")
            .is_none());

        let permissions = proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap()["execution"]["proposal"]["permissions"]
            .as_array_mut()
            .unwrap();
        permissions.retain(|permission| permission["profileId"] != "casework-review-status");
        let planned = plan(
            "correct-address",
            "single-reviewer-approval",
            &proposals,
            &actions,
            &access,
        )
        .unwrap();
        assert_eq!(
            planned.service_scopes,
            vec!["registry:proposal:review-status"]
        );
        let status_change = planned
            .changes
            .iter()
            .find(|change| change.path == "accessProfiles[id=correct-address-review-status]")
            .unwrap();
        assert_eq!(
            status_change.yaml["accessProfiles"][0]["requiredScopes"],
            json!(["registry:proposal:review-status"])
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_agreement_accepts_explicit_semantic_defaults_without_rewriting() {
        let temporary = crate::canonical_tempdir();
        let fake_root = temporary.path().join("fake");
        fs::create_dir(&fake_root).unwrap();
        let (proposals, actions, access) = facility_explanations();
        let bregctl = fake_bregctl(&fake_root, &proposals, &actions, &access, true, None);
        let project = temporary.path().join("review");
        let breg_project = temporary.path().join("breg-project");
        fs::create_dir(&breg_project).unwrap();
        add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap();

        let mut explicit = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        let policy = &mut explicit["reviewPolicies"]["facility-address-review"];
        for stage in policy["stages"].as_array_mut().unwrap() {
            let stage = stage.as_object_mut().unwrap();
            stage
                .entry("negativeDecisions")
                .or_insert_with(|| json!("settle"));
            stage
                .entry("excludeInitiator")
                .or_insert_with(|| json!(false));
            stage
                .entry("excludePreviousStageReviewers")
                .or_insert_with(|| json!(false));
        }
        for outcome in policy["outcomes"].as_object_mut().unwrap().values_mut() {
            outcome
                .as_object_mut()
                .unwrap()
                .entry("resultRequired")
                .or_insert_with(|| json!(false));
        }
        write_yaml(&project.join("casework.yaml"), &explicit).unwrap();
        let explicit_bytes = fs::read(project.join("casework.yaml")).unwrap();

        let rerun = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap();
        assert_eq!(rerun["outcome"], "in-agreement", "explicit policy defaults");
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            explicit_bytes
        );

        let mut mismatch = explicit.clone();
        mismatch["reviewPolicies"]["facility-address-review"]["stages"][0]["requiredApprovals"] =
            json!(2);
        write_yaml(&project.join("casework.yaml"), &mismatch).unwrap();
        let mismatch_bytes = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/reviewPolicies/facility-address-review/stages"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_bytes
        );

        write_yaml(&project.join("casework.yaml"), &explicit).unwrap();
        let mut mismatch = explicit;
        mismatch["reviewPolicies"]["facility-address-review"]["outcomes"]["approved"]["label"] =
            json!("Approve now");
        write_yaml(&project.join("casework.yaml"), &mismatch).unwrap();
        let mismatch_bytes = fs::read(project.join("casework.yaml")).unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert_eq!(
            failure.diagnostic().1,
            "/reviewPolicies/facility-address-review/outcomes"
        );
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            mismatch_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn changes_needed_and_refused_generation_leave_no_project() {
        let temporary = crate::canonical_tempdir();
        let breg_project = temporary.path().join("breg-project");
        fs::create_dir(&breg_project).unwrap();
        let (complete_proposals, actions, access) = facility_explanations();
        let mut missing_proposals = complete_proposals.clone();
        let proposal = missing_proposals["actions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|action| action["id"] == "correct-address")
            .unwrap();
        proposal["execution"]["proposal"]["review"] = Value::Null;
        proposal["execution"]["proposal"]["reviewContext"] = Value::Null;
        proposal["execution"]["proposal"]["permissions"] = json!([]);
        let missing_root = temporary.path().join("missing-fake");
        fs::create_dir(&missing_root).unwrap();
        let missing = fake_bregctl(
            &missing_root,
            &missing_proposals,
            &actions,
            &access,
            true,
            None,
        );
        let missing_project = temporary.path().join("missing-review");
        let refused = add(
            &missing_project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &missing,
        )
        .unwrap();
        assert_eq!(refused["ok"], false, "missing BReg configuration");
        assert_eq!(refused["outcome"], "changes-needed");
        assert!(refused.get("state").is_none());
        assert_eq!(
            refused["diagnostics"][0]["code"],
            "casework.provider-add.breg-changes-needed"
        );
        assert!(!missing_project.exists());

        let failing_root = temporary.path().join("failing-fake");
        fs::create_dir(&failing_root).unwrap();
        let failing = fake_bregctl(
            &failing_root,
            &complete_proposals,
            &actions,
            &access,
            false,
            None,
        );
        let failed_project = temporary.path().join("failed-review");
        let error = add(
            &failed_project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &failing,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::BregctlRefused { .. })
        ));
        assert!(!failed_project.exists());
    }

    #[cfg(unix)]
    #[test]
    fn breg_explain_and_diff_preserve_peer_exit_classes() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = crate::canonical_tempdir();
        let bregctl = temporary.path().join("bregctl");
        for (child_exit, expected_exit) in [
            (crate::DOMAIN_REFUSAL_EXIT, crate::DOMAIN_REFUSAL_EXIT),
            (
                crate::OPERATIONAL_FAILURE_EXIT,
                crate::OPERATIONAL_FAILURE_EXIT,
            ),
            (crate::report::USAGE_EXIT, crate::OPERATIONAL_FAILURE_EXIT),
            (64, crate::OPERATIONAL_FAILURE_EXIT),
        ] {
            fs::write(&bregctl, format!("#!/bin/sh\nexit {child_exit}\n")).unwrap();
            fs::set_permissions(&bregctl, fs::Permissions::from_mode(0o700)).unwrap();
            for error in [
                explain(&bregctl, temporary.path(), "actions")
                    .expect_err("the child explanation was refused"),
                breg_package_agrees_with_project(
                    &bregctl,
                    temporary.path(),
                    &temporary.path().join("package"),
                )
                .expect_err("the child package comparison was refused"),
            ] {
                let (exit, diagnostic) =
                    crate::classify_failure(crate::CommandKind::Authoring, &error);
                assert_eq!(exit, expected_exit, "child exit {child_exit}: {diagnostic}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn version_mismatch_leaves_no_destination() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = crate::canonical_tempdir();
        let bregctl = temporary.path().join("bregctl");
        fs::write(
            &bregctl,
            "#!/bin/sh\nprintf '%s\\n' 'bregctl incompatible-release-canary'\n",
        )
        .unwrap();
        fs::set_permissions(&bregctl, fs::Permissions::from_mode(0o700)).unwrap();
        let project = temporary.path().join("review");
        let error = add(
            &project,
            temporary.path(),
            "correct-address",
            "single-reviewer-approval",
            None,
            None,
            &bregctl,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::VersionMismatch)
        ));
        assert!(!project.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sealed_package_pairing_and_refusal_are_atomic_and_report_final_destinations() {
        let temporary = crate::canonical_tempdir();
        let breg_project = temporary.path().join("breg-project");
        fs::create_dir(&breg_project).unwrap();
        let (proposals, actions, access) = facility_explanations();

        let success_root = temporary.path().join("success-fake");
        fs::create_dir(&success_root).unwrap();
        let (package, digest) = native_package(&success_root, false);
        let matching_registry_revision = format!("sha256:{}", "0".repeat(64));
        let bregctl = fake_bregctl(
            &success_root,
            &proposals,
            &actions,
            &access,
            true,
            Some((&digest, &matching_registry_revision)),
        );
        let project = temporary.path().join("review");
        let package_output = project.join("build/sealed-casework");
        let created = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&package_output),
            &bregctl,
        )
        .unwrap();
        assert_eq!(created["ok"], true, "sealed package generation");
        assert_eq!(created["check"]["project"], json!(project));
        assert_eq!(created["package"]["output"], json!(package_output));
        assert!(project.is_dir());
        assert!(package_output.is_dir());
        let runtime_path = project.join("runtime.example.yaml");
        let runtime_bytes = fs::read(&runtime_path).unwrap();
        let runtime = Reader::new(runtime_path.display().to_string())
            .scan(&runtime_bytes)
            .unwrap()
            .unwrap()
            .to_json_value();
        assert_eq!(
            runtime["package"]["root"],
            json!(std::path::absolute(&package_output).unwrap())
        );
        let policy_before = fs::read(project.join("casework.yaml")).unwrap();
        let repeated = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&package_output),
            &bregctl,
        )
        .unwrap();
        assert_eq!(repeated["outcome"], "in-agreement", "sealed package rerun");
        assert_eq!(repeated["package"]["output"], json!(package_output));
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            policy_before
        );

        let rerun_output = temporary.path().join("rerun-package");
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&rerun_output),
            &bregctl,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::ExistingPackageOutputRequested)
        ));
        assert!(!rerun_output.exists());
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            policy_before
        );

        fs::write(package_output.join("SHA256SUMS"), b"mismatched\n").unwrap();
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&package_output),
            &bregctl,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::ExistingPackageOutputMismatch)
        ));
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            policy_before
        );

        let project_as_output = temporary.path().join("project-as-output");
        let error = add(
            &project_as_output,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&project_as_output),
            &bregctl,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::PackageDestinationIsProject)
        ));
        assert!(!project_as_output.exists());

        let traversed_project = temporary.path().join("traversed-review");
        let vanished_output = temporary.path().join("vanished-package");
        let traversed_output = traversed_project.join("../vanished-package");
        let error = add(
            &traversed_project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&package),
            Some(&traversed_output),
            &bregctl,
        )
        .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ProviderAddFailure>(),
            Some(ProviderAddFailure::PackageDestinationTraversesProject)
        ));
        assert!(!traversed_project.exists());
        assert!(!vanished_output.exists());

        let mismatch_root = temporary.path().join("mismatch-fake");
        fs::create_dir(&mismatch_root).unwrap();
        let (mismatched_package, mismatched_digest) = native_package(&mismatch_root, true);
        let stale_registry_revision = format!("sha256:{}", "a".repeat(64));
        let mismatched_bregctl = fake_bregctl(
            &mismatch_root,
            &proposals,
            &actions,
            &access,
            true,
            Some((&mismatched_digest, &stale_registry_revision)),
        );
        let error = add(
            &project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&mismatched_package),
            None,
            &mismatched_bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert!(matches!(failure, ProviderAddFailure::BregPackageMismatch));
        assert_eq!(
            fs::read(project.join("casework.yaml")).unwrap(),
            policy_before
        );

        let refused_project = temporary.path().join("refused-review");
        let refused_output = refused_project.join(".casework/package");
        let error = add(
            &refused_project,
            &breg_project,
            "correct-address",
            "single-reviewer-approval",
            Some(&mismatched_package),
            Some(&refused_output),
            &mismatched_bregctl,
        )
        .unwrap_err();
        let failure = error.downcast_ref::<ProviderAddFailure>().unwrap();
        assert!(matches!(failure, ProviderAddFailure::BregPackageMismatch));
        assert_eq!(
            failure.diagnostic().0,
            "casework.provider-add.breg-package-mismatch"
        );
        assert_eq!(failure.diagnostic().1, "--breg-package");
        assert!(!refused_project.exists());
        assert!(!refused_output.exists());
    }
}
