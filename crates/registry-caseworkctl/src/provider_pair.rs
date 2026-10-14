// SPDX-License-Identifier: Apache-2.0
//! Offline native producer agreement and read-only pairing. Never writes the producer.
use anyhow::{bail, Context, Result};
use registry_casework_breg::{BregContextExport, DESCRIPTION_API_VERSION, DESCRIPTION_KIND};
use registry_casework_core::{ContentDigest, ReviewContextContract, ReviewContextPolicy};
use registry_platform_config::{sha256_uri, verify_package, PackageLimits, VerifiedPackage};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn verify(package: &Path, bregctl: &Path) -> Result<(Value, VerifiedPackage)> {
    let version = Command::new(bregctl)
        .arg("--version")
        .output()
        .context("starting bregctl")?;
    let version = std::str::from_utf8(&version.stdout)?.trim();
    if !version.ends_with(registry_platform_buildinfo::DISPLAY_VERSION) {
        bail!("bregctl must be the same Registry Stack release");
    }
    let output = Command::new(bregctl)
        .args(["--format", "json", "check", "--package"])
        .arg(package)
        .output()
        .context("checking the native BReg package")?;
    if !output.status.success() {
        bail!("bregctl refused the native package; run bregctl check --package to inspect its diagnostics");
    }
    let report: Value = serde_json::from_slice(&output.stdout)?;
    if report["ok"] != true {
        bail!("native package check did not confirm a valid package");
    }
    // The checked producer package may be a mutable directory. Capture its
    // envelope and compare every imported byte to that exact verified digest.
    let verified = verify_package(package, &PackageLimits::default(), "bregctl package")?;
    if report["packageDigest"].as_str() != Some(verified.digest()) {
        bail!("native producer package changed after bregctl checked it");
    }
    Ok((report, verified))
}
fn captured_native_file(
    package: &Path,
    verified: &VerifiedPackage,
    relative: &str,
) -> Result<Vec<u8>> {
    let bytes = crate::project::read_package_input(&crate::project::project_input_path(
        package, relative,
    )?)?;
    if verified.file_digest(relative).as_deref() != Some(sha256_uri(&bytes).as_str()) {
        bail!("native producer package file changed after verification");
    }
    Ok(bytes)
}
fn native_export(
    package: &Path,
    action: &str,
    namespace: &str,
    verified: &VerifiedPackage,
) -> Result<BregContextExport> {
    if registry_platform_yaml::LocalId::new(action).is_err() {
        bail!("action ID must be a local identifier");
    }
    let index: Value = serde_json::from_slice(&captured_native_file(
        package,
        verified,
        "generated/review-context-schemas/index.json",
    )?)?;
    let contract = &index[action];
    let path = contract["path"]
        .as_str()
        .context("native action exports no review-context schema")?;
    let schema_bytes = String::from_utf8(captured_native_file(package, verified, path)?)?;
    let schema: Value = serde_json::from_str(&schema_bytes)?;
    let export = BregContextExport {
        api_version: DESCRIPTION_API_VERSION.into(),
        kind: DESCRIPTION_KIND.into(),
        source_namespace: namespace.into(),
        action_id: action.into(),
        context_id: schema["x-registry-review-context"]["contextId"]
            .as_str()
            .context("native schema lacks context ID")?
            .into(),
        contract: ReviewContextContract {
            id: contract["id"]
                .as_str()
                .context("native schema lacks contract ID")?
                .into(),
            revision: ContentDigest::parse(
                contract["revision"]
                    .as_str()
                    .context("native schema lacks revision")?,
            )?,
            schema_digest: ContentDigest::parse(
                contract["digest"]
                    .as_str()
                    .context("native schema lacks digest")?,
            )?,
        },
        schema,
        schema_bytes,
    };
    export.check()?;
    Ok(export)
}
pub(super) fn compare(
    project: &Path,
    package: &Path,
    provider_id: Option<&str>,
    bregctl: &Path,
) -> Result<Value> {
    let policy = crate::project::load_and_check_policy(project)?;
    let (report, verified) = verify(package, bregctl)?;
    let mut compared = Vec::new();
    for provider in &policy.context_providers {
        if provider_id.is_some_and(|id| id != provider.id) {
            continue;
        }
        let description = provider
            .description
            .as_deref()
            .context("provider has no native export; run caseworkctl provider pair")?;
        let export: BregContextExport =
            serde_json::from_slice(&crate::project::read_package_input(
                &crate::project::project_input_path(project, description)?,
            )?)?;
        export.check()?;
        let native = native_export(
            package,
            &export.action_id,
            &provider.source_namespace,
            &verified,
        )?;
        if native.contract != export.contract || native.schema_bytes != export.schema_bytes {
            bail!("native producer contract differs from the imported provider export; regenerate and recompile the review policy");
        }
        for review in &policy.review_policies {
            if let ReviewContextPolicy::CurrentSource {
                provider: id,
                contract,
            } = &review.context
            {
                if id == &provider.id && contract != &native.contract {
                    bail!("review policy context pin differs from native producer contract");
                }
            }
        }
        compared.push(json!({"providerId":provider.id,"contextContract":native.contract,"registryRevision":report["registryRevision"],"schemaDigest":sha256_uri(native.schema_bytes.as_bytes())}));
    }
    if compared.is_empty() {
        bail!("no matching context provider is declared");
    }
    Ok(
        json!({"package":package,"packageDigest":verified.digest(),"agreements":compared,"networkAccess":false,"databaseAccess":false}),
    )
}
pub(super) fn pair(
    project: &Path,
    id: &str,
    package: &Path,
    action: &str,
    bregctl: &Path,
    apply: bool,
) -> Result<Value> {
    let policy = crate::project::load_and_check_policy(project)?;
    let provider = policy
        .context_providers
        .iter()
        .find(|p| p.id == id)
        .context("context provider ID is not declared")?;
    let (report, verified) = verify(package, bregctl)?;
    let export = native_export(package, action, &provider.source_namespace, &verified)?;
    for review in &policy.review_policies {
        if let ReviewContextPolicy::CurrentSource {
            provider: id,
            contract,
        } = &review.context
        {
            if id == &provider.id && contract != &export.contract {
                bail!("policy context contract does not match the native export; vendor the native schema and pin its ID, revision and exact file digest first");
            }
        }
    }
    if provider.capabilities.iter().any(|cap| {
        !matches!(
            cap,
            registry_casework_core::ReviewContextCapability::HumanDisplay
                | registry_casework_core::ReviewContextCapability::ServiceStatus
        )
    }) {
        bail!("native BReg provider cannot expose minimized service-purpose fields");
    }
    let relative = provider
        .description
        .clone()
        .unwrap_or_else(|| format!("context-providers/{id}.json"));
    let file = project.join(&relative);
    if !relative.starts_with("context-providers/") || relative.contains("..") {
        bail!("provider description must be below context-providers");
    }
    if apply {
        fs::create_dir_all(file.parent().context("export path has no parent")?)?;
        let mut document = crate::project::read_project(project)?
            .document
            .to_json_value();
        let providers = document["contextProviders"]
            .as_array_mut()
            .context("contextProviders is required")?;
        providers
            .iter_mut()
            .find(|p| p["id"] == id)
            .context("provider disappeared")?["description"] = json!(relative);
        let bytes = serde_json::to_vec_pretty(&export)?;
        // Both replacements are prepared before mutation and never change BReg inputs.
        let policy_bytes = serde_norway::to_string(&document)?;
        let staged = tempfile::NamedTempFile::new_in(project)?;
        fs::write(staged.path(), policy_bytes)?;
        fs::write(&file, bytes)?;
        staged.persist(project.join("casework.yaml"))?;
    }
    Ok(
        json!({"ok":true,"command":"provider pair","applied":apply,"providerId":id,"description":relative,"contract":export.contract,"registryRevision":report["registryRevision"],"readerAuthority":{"profile":provider.service_profiles.get(&registry_casework_core::ReviewContextCapability::ServiceStatus),"operation":"get-review-status","sourceWrites":false},"next":"Bind the provider endpoint and status-reader secret references in runtime.yaml."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_export_binds_the_context_source_without_a_registry_revision_pin() {
        let temporary = crate::canonical_tempdir();
        let relative = "generated/review-context-schemas/context.schema.json";
        let schema_path = temporary.path().join(relative);
        fs::create_dir_all(schema_path.parent().unwrap()).unwrap();
        let mut schema = json!({"$schema":"https://json-schema.org/draft/2020-12/schema",
            "$id":"urn:registry:breg:review-context:registry:correct-address:address",
            "type":"object","additionalProperties":false,"properties":{},
            "x-registry-review-context":{"registryId":"registry","sourceNamespace":"review-source",
                "actionId":"correct-address","contextId":"address"}});
        let revision = sha256_uri(&serde_json::to_vec(&schema).unwrap());
        schema["x-registry-definition-revision"] = json!(revision);
        let bytes = serde_json::to_vec(&schema).unwrap();
        fs::write(&schema_path, &bytes).unwrap();
        fs::write(
            temporary
                .path()
                .join("generated/review-context-schemas/index.json"),
            serde_json::to_vec(
                &json!({"correct-address":{"id":schema["$id"],"revision":revision,
                "digest":sha256_uri(&bytes),"path":relative}}),
            )
            .unwrap(),
        )
        .unwrap();
        let verified = registry_platform_config::write_sum_file(
            temporary.path(),
            None,
            &PackageLimits::default(),
            "bregctl package",
        )
        .unwrap();
        let export = native_export(
            temporary.path(),
            "correct-address",
            "review-source",
            &verified,
        )
        .unwrap();
        assert_eq!(export.source_namespace, "review-source");
        assert!(serde_json::to_value(export)
            .unwrap()
            .get("registryRevision")
            .is_none());
        assert!(native_export(
            temporary.path(),
            "correct-address",
            "other-source",
            &verified
        )
        .is_err());
    }

    #[test]
    fn producer_file_changed_after_package_check_is_refused() {
        let temporary = crate::canonical_tempdir();
        let relative = "generated/review-context-schemas/index.json";
        let path = temporary.path().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"{}").unwrap();
        let verified = registry_platform_config::write_sum_file(
            temporary.path(),
            None,
            &PackageLimits::default(),
            "bregctl package",
        )
        .unwrap();
        assert_eq!(
            captured_native_file(temporary.path(), &verified, relative).unwrap(),
            b"{}"
        );
        fs::write(path, b"{\"changed\":true}").unwrap();
        assert!(captured_native_file(temporary.path(), &verified, relative).is_err());
    }
}
