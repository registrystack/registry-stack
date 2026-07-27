// SPDX-License-Identifier: Apache-2.0

const ARTIFACT_MANIFEST_FILE: &str = "artifact-manifest.json";
const REVIEW_ARTIFACT_ACTIONS: &[ArtifactAction] = &[
    ArtifactAction::Regenerate,
    ArtifactAction::Compare,
    ArtifactAction::Validate,
    ArtifactAction::Discard,
];
const BUNDLE_INPUT_ACTIONS: &[ArtifactAction] = &[
    ArtifactAction::Regenerate,
    ArtifactAction::Compare,
    ArtifactAction::Validate,
    ArtifactAction::Sign,
    ArtifactAction::Verify,
    ArtifactAction::Discard,
];

#[derive(Debug)]
struct GeneratedArtifactClassification {
    format_version: &'static str,
    classes: Vec<ArtifactClass>,
    sensitivity: ArtifactSensitivity,
    publication: ArtifactPublication,
    edit: ArtifactEditPolicy,
    version_control: ArtifactVersionControl,
    review: ArtifactReviewState,
    lifecycle: ArtifactLifecycle,
    actions: Vec<ArtifactAction>,
    consumers: Vec<ArtifactConsumer>,
}

fn write_artifact_manifest(
    temporary_root: &Path,
    project: &str,
    environment: &str,
    inputs: &[ArtifactInputDigest],
) -> Result<ProjectArtifactManifestRef> {
    validate_artifact_manifest_inputs(inputs)?;
    let build_prefix = format!("{BUILD_ROOT}/{environment}");
    let mut artifacts = collect_generated_artifacts(temporary_root, &build_prefix)?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = ProjectArtifactManifestV1 {
        schema_version: ProjectArtifactManifestSchemaVersion::V1,
        format_version: ProjectArtifactManifestFormatVersion::V1,
        project: project.to_string(),
        environment: environment.to_string(),
        generator: ArtifactGenerator {
            name: ArtifactGeneratorName::Registryctl,
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
        inputs: inputs.to_vec(),
        artifacts,
    };
    let manifest_bytes = canonical_json_line(
        &serde_json::to_value(&manifest).context("failed to serialize artifact manifest")?,
    )
    .context("failed to canonicalize artifact manifest")?;
    let manifest_path = temporary_root.join(ARTIFACT_MANIFEST_FILE);
    write_private_file(&manifest_path, &manifest_bytes)?;

    Ok(ProjectArtifactManifestRef {
        path: project_relative_path(format!("{build_prefix}/{ARTIFACT_MANIFEST_FILE}"))?,
        digest: sha256_digest(&manifest_bytes)?,
    })
}

fn validate_artifact_manifest_inputs(inputs: &[ArtifactInputDigest]) -> Result<()> {
    if inputs.is_empty() {
        bail!("artifact manifest requires per-file authored input provenance");
    }
    for input in inputs {
        if input.path.as_str().starts_with(".registry-stack/") {
            bail!("artifact manifest input provenance must name authored project files");
        }
    }
    if inputs.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        bail!("artifact manifest inputs must be sorted by unique project-relative path");
    }
    Ok(())
}

fn collect_generated_artifacts(
    temporary_root: &Path,
    build_prefix: &str,
) -> Result<Vec<GeneratedArtifactRecord>> {
    let metadata = fs::symlink_metadata(temporary_root).with_context(|| {
        format!(
            "failed to inspect temporary build root {}",
            temporary_root.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("temporary build root must be a real directory");
    }
    let mut artifacts = Vec::new();
    collect_generated_artifacts_under(
        temporary_root,
        temporary_root,
        build_prefix,
        &mut artifacts,
    )?;
    Ok(artifacts)
}

fn collect_generated_artifacts_under(
    temporary_root: &Path,
    directory: &Path,
    build_prefix: &str,
    artifacts: &mut Vec<GeneratedArtifactRecord>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read generated directory {}", directory.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| {
            format!(
                "failed to enumerate generated directory {}",
                directory.display()
            )
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(temporary_root)
            .map_err(|_| anyhow!("generated artifact escaped the temporary build root"))?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect generated entry {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!(
                "generated build contains a symlink, which is unsupported: {}",
                relative.display()
            );
        }
        if metadata.is_dir() {
            collect_generated_artifacts_under(temporary_root, &path, build_prefix, artifacts)?;
            continue;
        }
        if !metadata.is_file() {
            bail!(
                "generated build contains an unsupported file type: {}",
                relative.display()
            );
        }
        if relative == Path::new(ARTIFACT_MANIFEST_FILE) {
            continue;
        }

        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read generated artifact {}", path.display()))?;
        let classification = classify_generated_artifact(relative)?;
        artifacts.push(GeneratedArtifactRecord {
            path: project_relative_path(format!(
                "{build_prefix}/{}",
                normalized_relative_path(relative)?
            ))?,
            format_version: classification.format_version.to_string(),
            digest: sha256_digest(&bytes)?,
            classes: classification.classes,
            sensitivity: classification.sensitivity,
            publication: classification.publication,
            edit: classification.edit,
            version_control: classification.version_control,
            review: classification.review,
            lifecycle: classification.lifecycle,
            actions: classification.actions,
            consumers: classification.consumers,
        });
    }
    Ok(())
}

fn classify_generated_artifact(relative: &Path) -> Result<GeneratedArtifactClassification> {
    let path = normalized_relative_path(relative)?;
    let classification = if path == "reviewable/review.json" {
        artifact_classification(
            "registry.project.review.v1",
            &[ArtifactClass::ReviewRecord],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::NeedsReview,
            ArtifactLifecycle::UnsignedNonDeployable,
            REVIEW_ARTIFACT_ACTIONS,
            &[
                ArtifactConsumer::Operator,
                ArtifactConsumer::ProjectDocumentation,
            ],
        )
    } else if single_json_child(&path, "reviewable/entities/") {
        artifact_classification(
            "registry.project.entity.v1",
            &[ArtifactClass::Documentation, ArtifactClass::ReviewRecord],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::NeedsReview,
            ArtifactLifecycle::UnsignedNonDeployable,
            REVIEW_ARTIFACT_ACTIONS,
            &[
                ArtifactConsumer::Operator,
                ArtifactConsumer::ProjectDocumentation,
            ],
        )
    } else if single_json_child(&path, "reviewable/integration-packs/") {
        artifact_classification(
            "registry.relay.integration-pack.v1",
            &[ArtifactClass::SourcePlan, ArtifactClass::ReviewRecord],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::NeedsReview,
            ArtifactLifecycle::UnsignedNonDeployable,
            REVIEW_ARTIFACT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::Operator,
                ArtifactConsumer::ProjectDocumentation,
            ],
        )
    } else if single_json_child(&path, "reviewable/consultation-contracts/") {
        artifact_classification(
            "registry.relay.consultation-contract.v1",
            &[
                ArtifactClass::ConsultationContract,
                ArtifactClass::ReviewRecord,
            ],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::NeedsReview,
            ArtifactLifecycle::UnsignedNonDeployable,
            REVIEW_ARTIFACT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::RegistryNotary,
                ArtifactConsumer::Operator,
                ArtifactConsumer::ProjectDocumentation,
            ],
        )
    } else if path == "private/relay/config/relay.yaml" {
        artifact_classification(
            "registry.relay.config.v1",
            &[ArtifactClass::RuntimeConfig, ArtifactClass::DeploymentInput],
            ArtifactSensitivity::TopologySensitive,
            ArtifactPublication::NeverPublish,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
                ArtifactConsumer::Operator,
            ],
        )
    } else if single_json_child(&path, "private/relay/config/artifacts/integration-packs/") {
        artifact_classification(
            "registry.relay.integration-pack.v1",
            &[ArtifactClass::SourcePlan, ArtifactClass::DeploymentInput],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
            ],
        )
    } else if single_json_child(
        &path,
        "private/relay/config/artifacts/consultation-contracts/",
    ) {
        artifact_classification(
            "registry.relay.consultation-contract.v1",
            &[
                ArtifactClass::ConsultationContract,
                ArtifactClass::DeploymentInput,
            ],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
            ],
        )
    } else if single_json_child(&path, "private/relay/config/artifacts/private-bindings/") {
        artifact_classification(
            "registry.relay.consultation-binding.v1",
            &[ArtifactClass::SourcePlan, ArtifactClass::DeploymentInput],
            ArtifactSensitivity::TopologySensitive,
            ArtifactPublication::NeverPublish,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
            ],
        )
    } else if two_level_json_child(&path, "private/relay/config/artifacts/evidence/") {
        artifact_classification(
            "registry.project.integration-evidence.v1",
            &[ArtifactClass::SourcePlan, ArtifactClass::DeploymentInput],
            ArtifactSensitivity::Internal,
            ArtifactPublication::OperatorOnly,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
            ],
        )
    } else if single_child_with_suffix(&path, "private/relay/config/artifacts/rhai/", ".rhai") {
        artifact_classification(
            "registry.relay.rhai-source.v1",
            &[ArtifactClass::SourcePlan, ArtifactClass::DeploymentInput],
            ArtifactSensitivity::TopologySensitive,
            ArtifactPublication::NeverPublish,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryRelay,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
            ],
        )
    } else if path == "private/relay/descriptors/operations.json" {
        operational_descriptor_classification(&[
            ArtifactConsumer::RegistryRelay,
            ArtifactConsumer::BundleSigner,
            ArtifactConsumer::DeploymentTooling,
            ArtifactConsumer::Operator,
        ])
    } else if path == "private/notary/descriptors/operations.json" {
        operational_descriptor_classification(&[
            ArtifactConsumer::RegistryNotary,
            ArtifactConsumer::BundleSigner,
            ArtifactConsumer::DeploymentTooling,
            ArtifactConsumer::Operator,
        ])
    } else if path == "private/relay/descriptors/secret-consumers.json" {
        secret_consumer_descriptor_classification(&[
            ArtifactConsumer::RegistryRelay,
            ArtifactConsumer::BundleSigner,
            ArtifactConsumer::DeploymentTooling,
            ArtifactConsumer::Operator,
        ])
    } else if path == "private/notary/descriptors/secret-consumers.json" {
        secret_consumer_descriptor_classification(&[
            ArtifactConsumer::RegistryNotary,
            ArtifactConsumer::BundleSigner,
            ArtifactConsumer::DeploymentTooling,
            ArtifactConsumer::Operator,
        ])
    } else if path == "private/relay/approval/review.json" {
        product_review_classification(
            "registry.project.review.v1",
            ArtifactReviewState::NeedsReview,
            ArtifactConsumer::RegistryRelay,
        )
    } else if path == "private/notary/approval/review.json" {
        product_review_classification(
            "registry.project.review.v1",
            ArtifactReviewState::NeedsReview,
            ArtifactConsumer::RegistryNotary,
        )
    } else if path == "private/relay/approval/project-state.json" {
        product_review_classification(
            APPROVAL_STATE_SCHEMA,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactConsumer::RegistryRelay,
        )
    } else if path == "private/notary/approval/project-state.json" {
        product_review_classification(
            APPROVAL_STATE_SCHEMA,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactConsumer::RegistryNotary,
        )
    } else if path == "private/notary/config/notary.yaml" {
        artifact_classification(
            "registry.notary.config.v1",
            &[
                ArtifactClass::RuntimeConfig,
                ArtifactClass::ClaimConfiguration,
                ArtifactClass::DeploymentInput,
            ],
            ArtifactSensitivity::TopologySensitive,
            ArtifactPublication::NeverPublish,
            ArtifactReviewState::GeneratedCandidate,
            ArtifactLifecycle::UnsignedNonDeployable,
            BUNDLE_INPUT_ACTIONS,
            &[
                ArtifactConsumer::RegistryNotary,
                ArtifactConsumer::BundleSigner,
                ArtifactConsumer::DeploymentTooling,
                ArtifactConsumer::Operator,
            ],
        )
    } else {
        bail!("generated artifact has no reviewed classification: {path}");
    };
    Ok(classification)
}

// The closed classification dimensions are intentionally visible together so
// every generated artifact review covers the whole publication boundary.
#[allow(clippy::too_many_arguments)]
fn artifact_classification(
    format_version: &'static str,
    classes: &[ArtifactClass],
    sensitivity: ArtifactSensitivity,
    publication: ArtifactPublication,
    review: ArtifactReviewState,
    lifecycle: ArtifactLifecycle,
    actions: &[ArtifactAction],
    consumers: &[ArtifactConsumer],
) -> GeneratedArtifactClassification {
    GeneratedArtifactClassification {
        format_version,
        classes: classes.to_vec(),
        sensitivity,
        publication,
        edit: ArtifactEditPolicy::GeneratedDoNotEdit,
        version_control: ArtifactVersionControl::Ignore,
        review,
        lifecycle,
        actions: actions.to_vec(),
        consumers: consumers.to_vec(),
    }
}

fn operational_descriptor_classification(
    consumers: &[ArtifactConsumer],
) -> GeneratedArtifactClassification {
    artifact_classification(
        "registry.project.operations.v1",
        &[ArtifactClass::DeploymentInput, ArtifactClass::Documentation],
        ArtifactSensitivity::Internal,
        ArtifactPublication::OperatorOnly,
        ArtifactReviewState::GeneratedCandidate,
        ArtifactLifecycle::UnsignedNonDeployable,
        BUNDLE_INPUT_ACTIONS,
        consumers,
    )
}

fn secret_consumer_descriptor_classification(
    consumers: &[ArtifactConsumer],
) -> GeneratedArtifactClassification {
    artifact_classification(
        "registry.project.secret-consumers.v1",
        &[ArtifactClass::DeploymentInput, ArtifactClass::Documentation],
        ArtifactSensitivity::TopologySensitive,
        ArtifactPublication::NeverPublish,
        ArtifactReviewState::GeneratedCandidate,
        ArtifactLifecycle::UnsignedNonDeployable,
        BUNDLE_INPUT_ACTIONS,
        consumers,
    )
}

fn product_review_classification(
    format_version: &'static str,
    review: ArtifactReviewState,
    product: ArtifactConsumer,
) -> GeneratedArtifactClassification {
    artifact_classification(
        format_version,
        &[ArtifactClass::ReviewRecord, ArtifactClass::DeploymentInput],
        ArtifactSensitivity::Internal,
        ArtifactPublication::OperatorOnly,
        review,
        ArtifactLifecycle::UnsignedNonDeployable,
        BUNDLE_INPUT_ACTIONS,
        &[
            product,
            ArtifactConsumer::BundleSigner,
            ArtifactConsumer::DeploymentTooling,
            ArtifactConsumer::Operator,
        ],
    )
}

fn single_json_child(path: &str, prefix: &str) -> bool {
    single_child_with_suffix(path, prefix, ".json")
}

fn single_child_with_suffix(path: &str, prefix: &str, suffix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|name| {
        !name.is_empty()
            && !name.contains('/')
            && name
                .strip_suffix(suffix)
                .is_some_and(|stem| !stem.is_empty())
    })
}

fn two_level_json_child(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix).is_some_and(|tail| {
        let Some((directory, file)) = tail.split_once('/') else {
            return false;
        };
        !directory.is_empty()
            && !file.is_empty()
            && !file.contains('/')
            && file
                .strip_suffix(".json")
                .is_some_and(|stem| !stem.is_empty())
    })
}

fn normalized_relative_path(path: &Path) -> Result<String> {
    let mut normalized = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            bail!(
                "generated artifact path is not normalized and relative: {}",
                path.display()
            );
        };
        let component = component
            .to_str()
            .ok_or_else(|| anyhow!("generated artifact path is not Unicode"))?;
        if !normalized.is_empty() {
            normalized.push('/');
        }
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        bail!("generated artifact path is empty");
    }
    Ok(normalized)
}

fn project_relative_path(path: impl Into<String>) -> Result<ProjectRelativePath> {
    ProjectRelativePath::new(path)
        .map_err(|error| anyhow!("invalid project-relative artifact path: {error}"))
}

fn sha256_digest(bytes: &[u8]) -> Result<Sha256Digest> {
    Sha256Digest::new(sha256_uri(bytes))
        .map_err(|error| anyhow!("failed to construct artifact digest: {error}"))
}

#[cfg(test)]
mod artifact_manifest_tests {
    use super::*;

    #[test]
    fn unclassified_generated_path_fails_closed() {
        let error = classify_generated_artifact(Path::new(
            "private/relay/config/artifacts/future/output.json",
        ))
        .expect_err("new generated path family must require an explicit classification");
        assert!(format!("{error:#}").contains("has no reviewed classification"));
    }
}
