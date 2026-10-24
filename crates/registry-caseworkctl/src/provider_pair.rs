// SPDX-License-Identifier: Apache-2.0
//! Offline native producer agreement and read-only pairing. Never writes the producer.
use anyhow::{bail, Context, Result};
use registry_casework_breg::{BregContextExport, DESCRIPTION_API_VERSION, DESCRIPTION_KIND};
use registry_casework_core::{ContentDigest, ReviewContextContract, ReviewContextPolicy};
use registry_platform_config::{sha256_uri, verify_package, PackageLimits, VerifiedPackage};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

/// Closed pairing causes keep diagnostics useful without rendering peer output.
#[derive(Debug)]
pub(super) enum PairingFailure {
    ContractMismatch { path: String },
    UnservedCapability { path: String },
    VersionMismatch,
}

impl PairingFailure {
    pub(super) fn diagnostic(&self) -> (&'static str, &str, &'static str, &'static str) {
        match self {
            Self::ContractMismatch { path } => (
                "casework.provider-pair.contract-mismatch", path,
                "policy context contract does not match the native export",
                "Vendor the native schema and pin its ID, revision and exact file digest at this path, then pair and recompile the review policy.",
            ),
            Self::UnservedCapability { path } => (
                "casework.provider-pair.unserved-capability", path,
                "native BReg provider cannot expose the requested service-purpose capability",
                "Remove the unserved capability at this path or select a provider that serves it, then pair again.",
            ),
            Self::VersionMismatch => (
                "casework.provider-pair.version-mismatch", "--bregctl-bin",
                "bregctl must be the same Registry Stack release as caseworkctl",
                "Select a bregctl executable from the same Registry Stack release with --bregctl-bin, then pair again.",
            ),
        }
    }
}

impl std::fmt::Display for PairingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.diagnostic().2)
    }
}
impl std::error::Error for PairingFailure {}

fn verify(package: &Path, bregctl: &Path) -> Result<(Value, VerifiedPackage)> {
    let version = Command::new(bregctl)
        .arg("--version")
        .output()
        .context("starting bregctl")?;
    let version = std::str::from_utf8(&version.stdout)?.trim();
    if !version.ends_with(registry_platform_buildinfo::DISPLAY_VERSION) {
        return Err(PairingFailure::VersionMismatch.into());
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
            return Err(PairingFailure::ContractMismatch {
                path: format!("/contextProviders/{}/description", provider.id),
            }
            .into());
        }
        for review in &policy.review_policies {
            if let ReviewContextPolicy::CurrentSource {
                provider: id,
                contract,
            } = &review.context
            {
                if id == &provider.id && contract != &native.contract {
                    return Err(PairingFailure::ContractMismatch {
                        path: format!("/reviewPolicies/{}/context/contract", review.id),
                    }
                    .into());
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
                return Err(PairingFailure::ContractMismatch {
                    path: format!("/reviewPolicies/{}/context/contract", review.id),
                }
                .into());
            }
        }
    }
    if provider
        .capabilities
        .iter()
        .any(|cap| !registry_casework_breg::SERVED_CAPABILITIES.contains(cap))
    {
        return Err(PairingFailure::UnservedCapability {
            path: format!("/contextProviders/{}/capabilities", provider.id),
        }
        .into());
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
            .as_object_mut()
            .context("contextProviders is required")?;
        providers.get_mut(id).context("provider disappeared")?["description"] = json!(relative);
        let bytes = serde_json::to_vec_pretty(&export)?;
        // Both replacements are prepared before mutation and never change BReg inputs.
        // An existing description already names this exact destination. Leave
        // authored bytes untouched in that common re-pairing case. Otherwise
        // normalize the YAML body, retaining its schema modeline and header notes.
        let staged = if provider.description.as_deref() == Some(relative.as_str()) {
            None
        } else {
            let original = crate::project::read_package_input(&project.join("casework.yaml"))?;
            let header: String = std::str::from_utf8(&original)?
                .split_inclusive('\n')
                .take_while(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
                .collect();
            let policy_bytes = format!("{header}{}", serde_norway::to_string(&document)?);
            let staged = tempfile::NamedTempFile::new_in(project)?;
            fs::write(staged.path(), policy_bytes)?;
            Some(staged)
        };
        fs::write(&file, bytes)?;
        if let Some(staged) = staged {
            staged.persist(project.join("casework.yaml"))?;
        }
    }
    let task_profile = provider
        .service_profiles
        .get(&registry_casework_core::ReviewContextCapability::TaskGrantContext);
    Ok(json!({
        "ok":true,"command":"provider pair","applied":apply,"providerId":id,
        "description":relative,"contract":export.contract,
        "registryRevision":report["registryRevision"],
        "readerAuthority":{"profile":provider.service_profiles.get(&registry_casework_core::ReviewContextCapability::ServiceStatus),"operation":"get-review-status","sourceWrites":false},
        "taskGrantAuthority":task_profile.map(|profile| json!({"profile":profile,"operation":"get-task-grant-context","sourceWrites":false})),
        "next":if task_profile.is_some() {"Bind the provider endpoint and its distinct statusProfile and taskGrantProfile settings in runtime.yaml."} else {"Bind the provider endpoint and status-reader secret references in runtime.yaml."}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_preserves_schema_header_exact_pins_and_existing_description_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::canonical_tempdir();
        let project = temporary.path().join("review");
        crate::project::init(&project, "canonical-review").unwrap();
        let policy_file = project.join("casework.yaml");
        let with_header_note = fs::read_to_string(&policy_file).unwrap().replacen(
            '\n',
            "\n# Retain this offline authoring header.\n",
            1,
        );
        fs::write(&policy_file, with_header_note).unwrap();
        let original = fs::read(&policy_file).unwrap();
        let original_value = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        let package = temporary.path().join("native-package");
        let relative = "generated/review-context-schemas/correct-address.schema.json";
        fs::create_dir_all(package.join("generated/review-context-schemas")).unwrap();
        let schema_bytes = fs::read(project.join("schemas/correct-address.schema.json")).unwrap();
        let schema: Value = serde_json::from_slice(&schema_bytes).unwrap();
        fs::write(package.join(relative), &schema_bytes).unwrap();
        fs::write(
            package.join("generated/review-context-schemas/index.json"),
            serde_json::to_vec(&json!({"correct-address":{
                "id":schema["$id"],"revision":schema["x-registry-definition-revision"],
                "digest":sha256_uri(&schema_bytes),"path":relative}}))
            .unwrap(),
        )
        .unwrap();
        let verified = registry_platform_config::write_sum_file(
            &package,
            None,
            &PackageLimits::default(),
            "bregctl package",
        )
        .unwrap();
        // The fixture CLI supplies only the version/package-check report;
        // pair still verifies the sealed native bytes and compiled policy.
        let bregctl = temporary.path().join("bregctl");
        fs::write(
            &bregctl,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  printf '%s\\n' 'bregctl {}'\nelse\n  printf '%s\\n' '{{\"ok\":true,\"packageDigest\":\"{}\"}}'\nfi\n",
                registry_platform_buildinfo::DISPLAY_VERSION,
                verified.digest()
            ),
        )
        .unwrap();
        fs::set_permissions(&bregctl, fs::Permissions::from_mode(0o700)).unwrap();
        let sums = fs::read(package.join("SHA256SUMS")).unwrap();
        let untouched = temporary.path().join("outside-destination.txt");
        fs::write(&untouched, b"preserved").unwrap();

        pair(
            &project,
            "facility-proposal-context",
            &package,
            "correct-address",
            &bregctl,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&policy_file).unwrap(), original);
        assert!(!project.join("context-providers").exists());
        pair(
            &project,
            "facility-proposal-context",
            &package,
            "correct-address",
            &bregctl,
            true,
        )
        .unwrap();
        let paired = fs::read_to_string(&policy_file).unwrap();
        assert!(paired.starts_with(
            std::str::from_utf8(&original)
                .unwrap()
                .lines()
                .next()
                .unwrap()
        ));
        assert!(paired.contains("# Retain this offline authoring header.\n"));
        assert!(paired.contains("\napiVersion: "));
        let description = project.join("context-providers/facility-proposal-context.json");
        let export: BregContextExport =
            serde_json::from_slice(&fs::read(&description).unwrap()).unwrap();
        assert_eq!(export.schema_bytes.as_bytes(), schema_bytes);
        let mut expected = original_value;
        expected["contextProviders"]["facility-proposal-context"]["description"] =
            json!("context-providers/facility-proposal-context.json");
        assert_eq!(
            crate::project::read_project(&project)
                .unwrap()
                .document
                .to_json_value(),
            expected
        );
        compare(
            &project,
            &package,
            Some("facility-proposal-context"),
            &bregctl,
        )
        .unwrap();

        let retained = paired.replace(
            "trustedProducers:",
            "# Keep this body note when pairing again.\ntrustedProducers:",
        );
        fs::write(&policy_file, &retained).unwrap();
        pair(
            &project,
            "facility-proposal-context",
            &package,
            "correct-address",
            &bregctl,
            true,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&policy_file).unwrap(), retained);
        assert_eq!(fs::read(package.join("SHA256SUMS")).unwrap(), sums);
        assert_eq!(fs::read(package.join(relative)).unwrap(), schema_bytes);
        assert_eq!(fs::read(&untouched).unwrap(), b"preserved");

        fs::write(package.join(relative), b"{}").unwrap();
        assert!(pair(
            &project,
            "facility-proposal-context",
            &package,
            "correct-address",
            &bregctl,
            true
        )
        .is_err());
        assert_eq!(fs::read_to_string(&policy_file).unwrap(), retained);
        assert_eq!(fs::read(&untouched).unwrap(), b"preserved");
    }

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
    #[test]
    fn pairing_refusal_names_contract_mismatch() {
        pairing_refusal(
            "contract-mismatch",
            "/reviewPolicies/facility-address-review/context/contract",
            "contract",
        );
    }

    #[test]
    fn pairing_refusal_names_unserved_capability() {
        pairing_refusal(
            "unserved-capability",
            "/contextProviders/facility-proposal-context/capabilities",
            "capability",
        );
    }

    #[test]
    fn pairing_refusal_names_version_mismatch() {
        let flag = PairingFailure::VersionMismatch.diagnostic().1;
        pairing_refusal("version-mismatch", flag, "release");
        for arguments in [
            vec![
                "caseworkctl",
                "provider",
                "pair",
                "review",
                "--provider-id",
                "source",
                "--breg-package",
                "package",
                "--action-id",
                "submit",
                flag,
                "matching-bregctl",
            ],
            vec!["caseworkctl", "check", "review", flag, "matching-bregctl"],
        ] {
            crate::command()
                .try_get_matches_from(arguments)
                .expect("both commands accept the diagnostic's suggested flag");
        }
    }

    fn pairing_refusal(cause: &str, pointer: &str, message: &str) {
        use std::os::unix::fs::PermissionsExt;
        let temporary = crate::canonical_tempdir();
        let project = temporary.path().join("review");
        crate::project::init(&project, "canonical-review").unwrap();
        let policy_file = project.join("casework.yaml");
        let with_header_note = fs::read_to_string(&policy_file).unwrap().replacen(
            '\n',
            "\n# Retain this offline authoring header.\n",
            1,
        );
        fs::write(&policy_file, with_header_note).unwrap();
        let original_value = crate::project::read_project(&project)
            .unwrap()
            .document
            .to_json_value();
        let package = temporary.path().join("native-package");
        let relative = "generated/review-context-schemas/correct-address.schema.json";
        fs::create_dir_all(package.join("generated/review-context-schemas")).unwrap();
        let schema_bytes = fs::read(project.join("schemas/correct-address.schema.json")).unwrap();
        let schema: Value = serde_json::from_slice(&schema_bytes).unwrap();
        fs::write(package.join(relative), &schema_bytes).unwrap();
        fs::write(
            package.join("generated/review-context-schemas/index.json"),
            serde_json::to_vec(&json!({"correct-address":{
                "id":schema["$id"],"revision":schema["x-registry-definition-revision"],
                "digest":sha256_uri(&schema_bytes),"path":relative}}))
            .unwrap(),
        )
        .unwrap();
        let verified = registry_platform_config::write_sum_file(
            &package,
            None,
            &PackageLimits::default(),
            "bregctl package",
        )
        .unwrap();
        // The fixture CLI supplies only the version/package-check report;
        // pair still verifies the sealed native bytes and compiled policy.
        let bregctl = temporary.path().join("bregctl");
        fs::write(
            &bregctl,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  printf '%s\\n' 'bregctl {}'\nelse\n  printf '%s\\n' '{{\"ok\":true,\"packageDigest\":\"{}\"}}'\nfi\n",
                registry_platform_buildinfo::DISPLAY_VERSION,
                verified.digest()
            ),
        )
        .unwrap();
        fs::set_permissions(&bregctl, fs::Permissions::from_mode(0o700)).unwrap();

        {
            let mut authored = original_value.clone();
            match cause {
                "contract-mismatch" => {
                    authored["reviewPolicies"]["facility-address-review"]["context"]["contract"]
                        ["revision"] = json!(format!("sha256:{}", "a".repeat(64)));
                }
                "unserved-capability" => {
                    authored["contextProviders"]["facility-proposal-context"]["capabilities"]
                        .as_array_mut()
                        .unwrap()
                        .push(json!("routing-context"));
                }
                "version-mismatch" => {
                    fs::write(
                        &bregctl,
                        "#!/bin/sh\nprintf '%s\\n' 'bregctl incompatible-release-canary'\n",
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            fs::write(&policy_file, serde_norway::to_string(&authored).unwrap()).unwrap();
            let error = pair(
                &project,
                "facility-proposal-context",
                &package,
                "correct-address",
                &bregctl,
                false,
            )
            .expect_err("pairing must refuse this configuration");
            let original_cause = match cause {
                "contract-mismatch" => "policy context contract does not match",
                "unserved-capability" => "native BReg provider cannot expose",
                "version-mismatch" => "bregctl must be the same",
                _ => unreachable!(),
            };
            assert!(
                error.to_string().contains(original_cause),
                "unexpected fixture refusal: {error}"
            );
            let (exit, diagnostic) = crate::classify_failure(crate::CommandKind::Authoring, &error);
            assert_eq!(exit, 1);
            assert_eq!(
                diagnostic["code"],
                format!("casework.provider-pair.{cause}")
            );
            assert_eq!(diagnostic["path"], pointer);
            assert!(diagnostic["message"].as_str().unwrap().contains(message));
            assert!(diagnostic["suggestedAction"].as_str().unwrap().len() > 20);
            assert!(!diagnostic
                .to_string()
                .contains("incompatible-release-canary"));
            assert!(!project.join("context-providers").exists());
        }
    }
}
