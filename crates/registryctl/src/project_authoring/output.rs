// SPDX-License-Identifier: Apache-2.0

include!("artifact_manifest.rs");

/// Trusted process-local dependencies used while executing project fixtures.
///
/// The worker executable is supplied only by reviewed Rust callers. It is not
/// derived from authored project state, CLI options, or environment variables.
#[derive(Clone, Debug)]
pub struct ProjectExecutionContext {
    worker_program: PathBuf,
}

impl ProjectExecutionContext {
    /// Uses the currently running `registryctl` executable for fixture workers.
    pub fn for_current_executable() -> Result<Self> {
        let worker_program =
            std::env::current_exe().context("current executable is unavailable")?;
        Self::new(worker_program)
    }

    /// Creates a context with an explicitly injected worker executable.
    ///
    /// The path must be absolute and identify an existing, non-symlink regular
    /// file with executable permissions. Validation happens before the path can
    /// reach either Relay or Notary worker configuration.
    pub fn new(worker_program: impl AsRef<Path>) -> Result<Self> {
        let worker_program = worker_program.as_ref();
        if !worker_program.is_absolute() {
            bail!("project worker executable path must be absolute");
        }
        let metadata = fs::symlink_metadata(worker_program)
            .context("project worker executable is unavailable")?;
        if metadata.file_type().is_symlink() {
            bail!("project worker executable must not be a symlink");
        }
        if !metadata.file_type().is_file() {
            bail!("project worker executable is not a regular file");
        }
        validate_project_worker_executable_permissions(&metadata)?;
        Ok(Self {
            worker_program: worker_program.to_path_buf(),
        })
    }

    fn worker_program(&self) -> &Path {
        &self.worker_program
    }
}

#[cfg(unix)]
fn validate_project_worker_executable_permissions(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("project worker executable is not executable");
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_project_worker_executable_permissions(_metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod project_execution_context_tests {
    use super::*;

    #[test]
    fn current_executable_is_a_valid_default_worker_program() {
        ProjectExecutionContext::for_current_executable()
            .expect("the current executable is an absolute real executable");
    }

    #[test]
    fn explicit_worker_program_rejects_missing_relative_and_directory_paths() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let missing = temporary.path().join("missing-worker");
        assert!(ProjectExecutionContext::new(&missing).is_err());
        assert!(ProjectExecutionContext::new(Path::new("relative-worker")).is_err());
        assert!(ProjectExecutionContext::new(temporary.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_worker_program_rejects_symlinks_and_non_executable_files() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temporary = tempfile::tempdir().expect("temporary directory");
        let non_executable = temporary.path().join("non-executable-worker");
        fs::write(&non_executable, b"not executable").expect("worker file writes");
        fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o600))
            .expect("worker permissions update");
        assert!(ProjectExecutionContext::new(&non_executable).is_err());

        let executable = temporary.path().join("worker");
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("worker file writes");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("worker permissions update");
        let link = temporary.path().join("worker-link");
        symlink(&executable, &link).expect("worker symlink creates");
        assert!(ProjectExecutionContext::new(&link).is_err());
        ProjectExecutionContext::new(&executable).expect("real executable is accepted");
    }
}

fn validate_generated_product_configs(compiled: &CompiledProject) -> Result<()> {
    if compiled.relay_private.is_empty() && compiled.notary_private.is_empty() {
        bail!("generated deployment has no product configuration");
    }
    if !compiled.relay_private.is_empty() {
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        validate_generated_relay(relay_config, &compiled.relay_private, "config/relay.yaml")?;
        if let Some(consultation_config) = compiled
            .relay_private
            .get(Path::new("config/relay-consultation.yaml"))
        {
            validate_generated_relay(
                consultation_config,
                &compiled.relay_private,
                "config/relay-consultation.yaml",
            )?;
        }
    }
    if !compiled.notary_private.is_empty() {
        validate_generated_notary(compiled)?;
    }
    Ok(())
}

fn validate_project_workbook_inputs(
    loaded: &LoadedRegistryProject,
    compiled: &CompiledProject,
) -> Result<Vec<ArtifactInputDigest>> {
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("workbook validation requires an explicit environment"))?;
    let workbook_bindings = environment
        .entities
        .iter()
        .filter(|(_, binding)| matches!(binding.provider, RecordProvider::Xlsx { .. }))
        .collect::<Vec<_>>();
    if workbook_bindings.is_empty() {
        return Ok(loaded.artifact_inputs.clone());
    }

    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("workbook validation requires generated Relay configuration"))?;
    let relay: registry_relay::config::Config = serde_norway::from_slice(relay_config)
        .map_err(|_| anyhow!("generated Relay configuration is invalid"))?;
    let mut workbooks = BTreeMap::<
        String,
        (
            PathBuf,
            Vec<(registry_relay::config::ResourceConfig, u64, u64)>,
        ),
    >::new();
    for (entity_id, binding) in workbook_bindings {
        let RecordProvider::Xlsx { project_file, .. } = &binding.provider else {
            unreachable!("workbook bindings are filtered above");
        };
        let entity = &loaded
            .entities
            .get(entity_id)
            .ok_or_else(|| anyhow!("workbook binding has no generated entity"))?
            .document;
        let resource_id = entity_materialization_resource_id(entity, binding)?;
        let resources = relay
            .datasets
            .iter()
            .flat_map(registry_relay::config::DatasetConfig::table_configs)
            .filter(|resource| resource.id.as_str() == resource_id)
            .cloned()
            .collect::<Vec<_>>();
        if resources.len() != 1 {
            bail!("workbook binding has no exact generated Relay resource");
        }
        let resource = resources
            .into_iter()
            .next()
            .expect("exactly one generated Relay resource was checked");
        let max_records = entity.materialization.max_records;
        let max_bytes = parse_entity_generation_bytes(&entity.materialization.max_bytes)?;
        let relative = project_file
            .to_str()
            .ok_or_else(|| anyhow!("workbook source path is invalid"))?
            .to_string();
        let entry = workbooks
            .entry(relative)
            .or_insert_with(|| (project_file.clone(), Vec::new()));
        entry.1.push((resource, max_records, max_bytes));
    }

    let byte_limit = registry_relay::ingest::xlsx_source_byte_limit(&relay);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| anyhow!("workbook validation runtime is unavailable"))?;
    let mut inputs = loaded
        .artifact_inputs
        .iter()
        .cloned()
        .map(|input| (input.path.as_str().to_string(), input))
        .collect::<BTreeMap<_, _>>();
    for (relative, (project_file, resources)) in workbooks {
        let bytes = read_project_workbook(&loaded.root, &project_file, byte_limit)?;
        for (resource, max_records, max_bytes) in resources {
            runtime
                .block_on(
                    registry_relay::ingest::validate_xlsx_source_bytes_with_limits(
                        &relay,
                        &resource,
                        &bytes,
                        Some((max_records, max_bytes)),
                    ),
                )
                .map_err(|error| anyhow!("workbook validation failed ({})", error.code()))?;
        }
        let input = ArtifactInputDigest {
            path: ProjectRelativePath::new(relative.clone())
                .map_err(|_| anyhow!("workbook source path is invalid"))?,
            digest: Sha256Digest::new(sha256_uri(&bytes))
                .map_err(|_| anyhow!("workbook source digest is invalid"))?,
            classification: ArtifactInputClassification::OperatorOwnedSourceData,
        };
        if inputs.insert(relative, input).is_some() {
            bail!("workbook source path overlaps an authored project input");
        }
    }
    Ok(inputs.into_values().collect())
}

fn read_project_workbook(root: &Path, relative: &Path, byte_limit: u64) -> Result<Vec<u8>> {
    let path = root.join(relative);
    reject_symlink_components(root, &path)
        .map_err(|_| anyhow!("workbook source input is not a contained regular file"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| anyhow!("workbook source input is missing or unreadable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > byte_limit {
        bail!("workbook source input is missing, unreadable, or exceeds the Relay byte limit");
    }
    let read_limit = byte_limit
        .checked_add(1)
        .ok_or_else(|| anyhow!("workbook source byte limit is invalid"))?;
    let file = fs::File::open(&path)
        .map_err(|_| anyhow!("workbook source input is missing or unreadable"))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| anyhow!("workbook source input exceeds the Relay byte limit"))?,
    );
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("workbook source input is unreadable"))?;
    if u64::try_from(bytes.len())
        .map_err(|_| anyhow!("workbook source input exceeds the Relay byte limit"))?
        > byte_limit
    {
        bail!("workbook source input exceeds the Relay byte limit");
    }
    Ok(bytes)
}

fn validate_generated_notary(compiled: &CompiledProject) -> Result<()> {
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary: StandaloneRegistryNotaryConfig =
        serde_norway::from_slice(notary_config).context("generated Notary config did not parse")?;
    notary
        .validate()
        .context("generated Notary config failed the production validator")?;
    Ok(())
}

fn validate_generated_relay(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    config_relative_path: &str,
) -> Result<()> {
    validate_generated_relay_activation(relay_config, files, config_relative_path)?;
    let config: Value = serde_norway::from_slice(relay_config)
        .context("generated Relay config did not parse as strict YAML")?;
    if config
        .pointer("/consultation/artifacts/public_contracts")
        .and_then(Value::as_array)
        .is_some_and(|contracts| !contracts.is_empty())
    {
        compile_generated_relay_fixture(relay_config, files, None).map(drop)?;
    }
    Ok(())
}

fn validate_generated_relay_activation(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    config_relative_path: &str,
) -> Result<()> {
    let validation_root = GeneratedValidationDirectory::create()?;
    write_file_map(&validation_root.path, files)?;
    let config_path = validation_root.path.join(config_relative_path);
    let mut local_config: Value = serde_norway::from_slice(relay_config)
        .context("generated Relay config did not parse for activation validation")?;
    local_config["deployment"]["profile"] = Value::String("local".to_string());
    materialize_generated_relay_validation_fingerprints(&mut local_config, &validation_root.path)?;
    fs::remove_file(&config_path)
        .context("failed to stage generated Relay activation validation")?;
    write_private_file(
        &config_path,
        serde_norway::to_string(&local_config)?.as_bytes(),
    )?;
    let mut loaded = registry_relay::config::load_with_metadata(&config_path)
        .map_err(|_| anyhow!("generated Relay config failed production loading"))?;
    if let Some(artifacts) = loaded.consultation_artifacts.take() {
        registry_relay::consultation::ConsultationService::validate_configuration(
            &loaded.runtime,
            artifacts,
        )
        .map_err(|_| {
            anyhow!("generated Relay config failed production consultation activation validation")
        })?;
    }
    Ok(())
}

fn materialize_generated_relay_validation_fingerprints(
    config: &mut Value,
    validation_root: &Path,
) -> Result<()> {
    let Some(api_keys) = config
        .pointer_mut("/auth/api_keys")
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };
    let mut references = BTreeMap::<String, (PathBuf, String)>::new();
    for key in api_keys {
        let Some(fingerprint) = key
            .as_object_mut()
            .and_then(|key| key.get_mut("fingerprint"))
        else {
            continue;
        };
        let Some(reference) = fingerprint.as_object() else {
            continue;
        };
        if reference.len() != 2 || reference.get("provider").and_then(Value::as_str) != Some("env")
        {
            continue;
        }
        let Some(name) = reference
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        let next_index = references.len() + 1;
        let (path, synthetic) = references
            .entry(name.to_string())
            .or_insert_with(|| {
                (
                    validation_root.join(format!("api-key-fingerprint-{next_index}")),
                    format!("sha256:{next_index:064x}"),
                )
            })
            .clone();
        if !path.exists() {
            write_private_file(&path, synthetic.as_bytes())
                .map_err(|_| anyhow!("failed to stage a generated Relay validation credential"))?;
        }
        *fingerprint = json!({
            "provider": "file",
            "path": path,
        });
    }
    Ok(())
}

struct GeneratedValidationDirectory {
    path: PathBuf,
}

impl GeneratedValidationDirectory {
    fn create() -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .context("failed to create generated validation directory identity")?;
            let path = std::env::temp_dir().join(format!(
                "registryctl-project-validation-{}-{}",
                std::process::id(),
                hex::encode(random)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("failed to create generated validation directory")
                }
            }
        }
        bail!("failed to allocate a unique generated validation directory")
    }
}

impl Drop for GeneratedValidationDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn compile_generated_relay_fixture(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    worker_program: Option<&Path>,
) -> Result<registry_relay::offline_fixture::OfflineRelayFixture> {
    let runtime: registry_relay::config::Config = serde_norway::from_slice(relay_config)
        .context("generated Relay config did not parse with the production model")?;
    registry_relay::config::validate::run(&runtime)
        .map_err(|_| anyhow!("generated Relay config failed the production startup validator"))?;
    let config: Value = serde_norway::from_slice(relay_config)
        .context("generated Relay config did not parse as strict YAML")?;
    let artifacts = config
        .pointer("/consultation/artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("generated Relay consultation artifact closure is absent"))?;
    let public = generated_pinned_artifacts(files, artifacts, "public_contracts")?;
    let packs = generated_pinned_artifacts(files, artifacts, "integration_packs")?;
    let bindings = generated_binding_artifacts(files, artifacts)?;
    let evidence = generated_evidence(files, artifacts)?;
    let public_refs = public
        .iter()
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let pack_refs = packs
        .iter()
        .map(|(bytes, hash)| PinnedSourcePlanArtifact::new(bytes, hash))
        .collect::<Vec<_>>();
    let binding_refs = bindings.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let evidence_refs = evidence
        .iter()
        .map(|(class, bytes, hash)| PinnedEvidenceArtifact::new(*class, bytes, hash))
        .collect::<Vec<_>>();
    let bundle = SourcePlanArtifactBundle::new(&public_refs, &pack_refs, &binding_refs)
        .with_evidence(&evidence_refs);
    match worker_program {
        Some(worker_program) => {
            registry_relay::offline_fixture::OfflineRelayFixture::compile_with_worker_program(
                &bundle,
                worker_program.to_path_buf(),
            )
        }
        None => registry_relay::offline_fixture::OfflineRelayFixture::compile(&bundle),
    }
    .context("generated Relay artifacts failed the production source-plan compiler")
}

fn generated_pinned_artifacts(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
    field: &str,
) -> Result<Vec<(Vec<u8>, String)>> {
    closure
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay artifact list {field} is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated artifact path is invalid"))?;
            let hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated typed artifact hash is invalid"))?;
            let raw_hash = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated raw artifact hash is invalid"))?;
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated artifact is not vendored in Relay input"))?;
            if sha256_uri(bytes) != raw_hash {
                bail!("generated artifact raw digest does not match its vendored bytes");
            }
            Ok((bytes.to_vec(), hash.to_owned()))
        })
        .collect()
}

fn generated_binding_artifacts(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
) -> Result<Vec<Vec<u8>>> {
    closure
        .get("private_bindings")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay private binding closure is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated artifact path is invalid"))?;
            let expected_hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated private binding typed hash is invalid"))?;
            let expected_raw = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated private binding raw hash is invalid"))?;
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated artifact is not vendored in Relay input"))?;
            if sha256_uri(bytes) != expected_raw {
                bail!("generated private binding raw digest does not match its vendored bytes");
            }
            let binding = compile_private_binding(bytes)
                .context("generated private binding failed exact typed revalidation")?;
            if binding.typed_hash() != expected_hash {
                bail!(
                    "generated private binding typed hash does not match its normalized identity"
                );
            }
            Ok(bytes.to_vec())
        })
        .collect()
}

fn generated_evidence(
    files: &BTreeMap<PathBuf, Box<[u8]>>,
    closure: &Map<String, Value>,
) -> Result<Vec<(EvidenceClass, Vec<u8>, String)>> {
    closure
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("generated Relay evidence closure is invalid"))?
        .iter()
        .map(|entry| {
            let path = entry
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated evidence path is invalid"))?;
            let class = match entry.get("class").and_then(Value::as_str) {
                Some("conformance") => EvidenceClass::Conformance,
                Some("negative_security") => EvidenceClass::NegativeSecurity,
                Some("minimization") => EvidenceClass::Minimization,
                _ => bail!("generated evidence class is invalid"),
            };
            let bytes = files
                .get(&Path::new("config").join(path))
                .ok_or_else(|| anyhow!("generated evidence is not vendored in Relay input"))?;
            let hash = entry
                .get("sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("generated evidence hash is invalid"))?
                .to_string();
            if sha256_uri(bytes) != hash {
                bail!("generated evidence digest does not match its vendored bytes");
            }
            Ok((class, bytes.to_vec(), hash))
        })
        .collect()
}

fn write_compiled_project(
    root: &Path,
    output: &Path,
    compiled: &CompiledProject,
    runtime_identity: Option<crate::RuntimeIdentity>,
    project: &str,
    environment: &str,
    artifact_inputs: &[ArtifactInputDigest],
) -> Result<ProjectArtifactManifestRef> {
    let expected_parent = root.join(BUILD_ROOT);
    let parent = output
        .parent()
        .ok_or_else(|| anyhow!("generated output has no parent"))?;
    if parent != expected_parent || output.file_name().is_none() {
        bail!("generated output must remain under the selected environment build root");
    }
    reject_symlink_components(root, &expected_parent)?;
    fs::create_dir_all(&expected_parent)
        .with_context(|| format!("failed to create {}", expected_parent.display()))?;
    reject_symlink_components(root, &expected_parent)?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("generated output name is invalid"))?;
    let temporary = expected_parent.join(format!(".{name}.tmp-{}", std::process::id()));
    if temporary.exists() {
        fs::remove_dir_all(&temporary)
            .with_context(|| format!("failed to remove stale {}", temporary.display()))?;
    }
    create_dir_owner_only(&temporary)?;
    let reviewable_root = temporary.join("reviewable");
    create_dir_owner_only(&reviewable_root)?;
    write_file_map(&reviewable_root, &compiled.reviewable)?;
    let review_bytes = canonical_json_line(&compiled.review)?;
    let approval_state_bytes = canonical_json_line(&compiled.approval_state)?;
    write_private_file(&reviewable_root.join("review.json"), &review_bytes)?;
    if !compiled.relay_private.is_empty() {
        let relay_root = temporary.join("private/relay");
        create_dir_owner_only(&relay_root)?;
        write_file_map(&relay_root, &compiled.relay_private)?;
        write_private_file(&relay_root.join(APPROVAL_REVIEW_PATH), &review_bytes)?;
        write_private_file(&relay_root.join(APPROVAL_STATE_PATH), &approval_state_bytes)?;
    }
    if !compiled.notary_private.is_empty() {
        let notary_root = temporary.join("private/notary");
        create_dir_owner_only(&notary_root)?;
        write_file_map(&notary_root, &compiled.notary_private)?;
        write_private_file(&notary_root.join(APPROVAL_REVIEW_PATH), &review_bytes)?;
        write_private_file(
            &notary_root.join(APPROVAL_STATE_PATH),
            &approval_state_bytes,
        )?;
    }
    if let Some(identity) = runtime_identity {
        // The temporary build root is freshly created owner-only state and is
        // not published until the rename below. Privileged ownership changes
        // are confined to the two config trees mounted into containers, so a
        // failure leaves the prior published build untouched.
        for relative in ["private/relay/config", "private/notary/config"] {
            assign_unpublished_runtime_input_owner(&temporary.join(relative), identity)?;
        }
    }
    let artifact_manifest =
        write_artifact_manifest(&temporary, project, environment, artifact_inputs)?;

    let backup = expected_parent.join(format!(".{name}.previous-{}", std::process::id()));
    if backup.exists() {
        fs::remove_dir_all(&backup)
            .with_context(|| format!("failed to remove stale {}", backup.display()))?;
    }
    if output.exists() {
        reject_symlink(output)?;
        fs::rename(output, &backup)
            .with_context(|| format!("failed to stage prior build {}", output.display()))?;
    }
    if let Err(error) = fs::rename(&temporary, output) {
        if backup.exists() {
            let _ = fs::rename(&backup, output);
        }
        return Err(error).with_context(|| format!("failed to publish {}", output.display()));
    }
    if backup.exists() {
        fs::remove_dir_all(&backup)
            .with_context(|| format!("failed to remove prior build {}", backup.display()))?;
    }
    Ok(artifact_manifest)
}

#[cfg(unix)]
fn assign_unpublished_runtime_input_owner(
    path: &Path,
    identity: crate::RuntimeIdentity,
) -> Result<()> {
    use std::os::unix::fs::{lchown, MetadataExt};

    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect unpublished runtime input {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        bail!(
            "unpublished runtime input contains an unsupported file type: {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path).with_context(|| {
            format!(
                "failed to read unpublished runtime input {}",
                path.display()
            )
        })? {
            let child = entry
                .with_context(|| {
                    format!(
                        "failed to read an entry under unpublished runtime input {}",
                        path.display()
                    )
                })?
                .path();
            assign_unpublished_runtime_input_owner(&child, identity)?;
        }
    }
    if metadata.uid() != identity.uid || metadata.gid() != identity.gid {
        lchown(path, Some(identity.uid), Some(identity.gid)).with_context(|| {
            format!(
                "failed to assign unpublished runtime input {} to {}:{}; the prior generated build remains active",
                path.display(), identity.uid, identity.gid
            )
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn assign_unpublished_runtime_input_owner(
    _path: &Path,
    _identity: crate::RuntimeIdentity,
) -> Result<()> {
    Ok(())
}

fn write_file_map(root: &Path, files: &BTreeMap<PathBuf, Box<[u8]>>) -> Result<()> {
    for (relative, bytes) in files {
        validate_relative_authored_path(relative)?;
        write_private_file(&root.join(relative), bytes)?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("generated file has no parent"))?;
    create_dir_owner_only(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

fn copy_embedded_dir(source: &include_dir::Dir<'_>, destination: &Path) -> Result<()> {
    for entry in source.entries() {
        match entry {
            include_dir::DirEntry::Dir(directory) => {
                let target = destination.join(
                    directory
                        .path()
                        .file_name()
                        .ok_or_else(|| anyhow!("embedded starter directory has no file name"))?,
                );
                create_dir_owner_only(&target)?;
                copy_embedded_dir(directory, &target)?;
            }
            include_dir::DirEntry::File(file) => {
                let target = destination.join(
                    file.path()
                        .file_name()
                        .ok_or_else(|| anyhow!("embedded starter file has no file name"))?,
                );
                write_private_file(&target, file.contents())?;
            }
        }
    }
    Ok(())
}

fn validate_baseline_pair(against: Option<&Path>, anchor: Option<&Path>) -> Result<()> {
    if against.is_some() != anchor.is_some() {
        bail!("--against and --anchor must be supplied together");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ApprovedBaselineSetPaths<'a> {
    against: Option<&'a Path>,
    anchor: Option<&'a Path>,
    relay_against: Option<&'a Path>,
    relay_anchor: Option<&'a Path>,
    notary_against: Option<&'a Path>,
    notary_anchor: Option<&'a Path>,
}

impl<'a> ApprovedBaselineSetPaths<'a> {
    fn legacy(against: Option<&'a Path>, anchor: Option<&'a Path>) -> Self {
        Self {
            against,
            anchor,
            relay_against: None,
            relay_anchor: None,
            notary_against: None,
            notary_anchor: None,
        }
    }

    fn build(
        options: &'a ProjectBuildOptions,
        baselines: Option<&'a ProjectBuildBaselineSetOptions>,
    ) -> Self {
        Self {
            against: options.against.as_deref(),
            anchor: options.anchor.as_deref(),
            relay_against: baselines.and_then(|set| set.relay_against.as_deref()),
            relay_anchor: baselines.and_then(|set| set.relay_anchor.as_deref()),
            notary_against: baselines.and_then(|set| set.notary_against.as_deref()),
            notary_anchor: baselines.and_then(|set| set.notary_anchor.as_deref()),
        }
    }

    fn promotion(options: &'a ProjectPromotionOptions) -> Self {
        Self {
            against: options.against.as_deref(),
            anchor: options.anchor.as_deref(),
            relay_against: options.relay_against.as_deref(),
            relay_anchor: options.relay_anchor.as_deref(),
            notary_against: options.notary_against.as_deref(),
            notary_anchor: options.notary_anchor.as_deref(),
        }
    }
}

#[derive(Clone, Copy)]
enum BaselineSetCompleteness {
    AnyVerifiedProduct,
    CompleteTopologyWhenPresent,
}

impl VerifiedBaselineSet {
    fn is_empty(&self) -> bool {
        self.relay.is_none() && self.notary.is_none()
    }

    fn iter(&self) -> impl Iterator<Item = &VerifiedBaseline> {
        [self.relay.as_ref(), self.notary.as_ref()]
            .into_iter()
            .flatten()
    }

    fn common(&self) -> Option<&VerifiedBaseline> {
        self.relay.as_ref().or(self.notary.as_ref())
    }

    fn predecessor_manifest_identities(&self) -> Value {
        json!({
            "relay": self.relay.as_ref().map(|baseline| &baseline.verified_manifest),
            "notary": self.notary.as_ref().map(|baseline| &baseline.verified_manifest),
        })
    }

    fn insert(&mut self, baseline: VerifiedBaseline) -> Result<()> {
        match verified_baseline_product(&baseline)? {
            PromotionProjectedProduct::Relay if self.relay.is_none() => {
                self.relay = Some(baseline);
            }
            PromotionProjectedProduct::Notary if self.notary.is_none() => {
                self.notary = Some(baseline);
            }
            PromotionProjectedProduct::Relay | PromotionProjectedProduct::Notary => {
                bail!("approved baseline set contains a duplicate product")
            }
        }
        Ok(())
    }

    fn validate_common_signed_state(&self) -> Result<()> {
        let Some(common) = self.common() else {
            return Ok(());
        };
        if self.iter().any(|baseline| {
            baseline.approval_state != common.approval_state
                || baseline.approval_state_digest != common.approval_state_digest
                || baseline.review_digest != common.review_digest
        }) {
            bail!("approved product baselines do not share one signed project approval state");
        }
        Ok(())
    }
}

fn validate_approved_baseline_set_paths(paths: ApprovedBaselineSetPaths<'_>) -> Result<()> {
    validate_named_baseline_pair("--against", paths.against, "--anchor", paths.anchor)?;
    validate_named_baseline_pair(
        "--relay-against",
        paths.relay_against,
        "--relay-anchor",
        paths.relay_anchor,
    )?;
    validate_named_baseline_pair(
        "--notary-against",
        paths.notary_against,
        "--notary-anchor",
        paths.notary_anchor,
    )?;
    if paths.against.is_some() && (paths.relay_against.is_some() || paths.notary_against.is_some())
    {
        bail!("--against cannot be combined with product-specific baselines");
    }
    Ok(())
}

fn load_verified_approved_baseline_set(
    paths: ApprovedBaselineSetPaths<'_>,
    loaded: &LoadedRegistryProject,
    completeness: BaselineSetCompleteness,
) -> Result<VerifiedBaselineSet> {
    validate_approved_baseline_set_paths(paths)?;
    let mut baselines = VerifiedBaselineSet::default();
    if let Some(baseline) = load_verified_baseline(paths.against, paths.anchor, loaded)? {
        baselines.insert(baseline)?;
    } else {
        for (against, anchor, expected_product) in [
            (
                paths.relay_against,
                paths.relay_anchor,
                PromotionProjectedProduct::Relay,
            ),
            (
                paths.notary_against,
                paths.notary_anchor,
                PromotionProjectedProduct::Notary,
            ),
        ] {
            if let Some(baseline) = load_verified_baseline(against, anchor, loaded)? {
                if verified_baseline_product(&baseline)? != expected_product {
                    bail!("product-specific approved baseline has the wrong product");
                }
                baselines.insert(baseline)?;
            }
        }
    }
    baselines.validate_common_signed_state()?;
    if matches!(
        completeness,
        BaselineSetCompleteness::CompleteTopologyWhenPresent
    ) && !baselines.is_empty()
    {
        let environment = loaded
            .environment
            .as_ref()
            .ok_or_else(|| anyhow!("approved baseline comparison requires an environment"))?;
        let products = project_promotion_products(environment);
        let requires_relay = products.contains(&PromotionProjectedProduct::Relay);
        let requires_notary = products.contains(&PromotionProjectedProduct::Notary);
        if baselines.relay.is_some() != requires_relay
            || baselines.notary.is_some() != requires_notary
        {
            bail!("approved baseline set is incomplete for the selected product topology");
        }
    }
    Ok(baselines)
}

fn load_verified_baseline(
    against: Option<&Path>,
    anchor: Option<&Path>,
    loaded: &LoadedRegistryProject,
) -> Result<Option<VerifiedBaseline>> {
    let (Some(bundle), Some(anchor)) = (against, anchor) else {
        return Ok(None);
    };
    let verified = registry_platform_config::verify_config_bundle(bundle, anchor)
        .with_context(|| format!("failed to verify config bundle {}", bundle.display()))?;
    let environment = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("verified baseline requires an explicit environment"))?;
    if !matches!(
        verified.manifest.product.as_str(),
        "registry-relay" | "registry-notary"
    ) || verified.manifest.environment != environment
    {
        bail!("verified baseline manifest is not bound to this product environment");
    }
    let review_bytes =
        read_verified_bundle_payload(bundle, &verified.manifest, APPROVAL_REVIEW_PATH, "review")?;
    let approval_state_bytes = read_verified_bundle_payload(
        bundle,
        &verified.manifest,
        APPROVAL_STATE_PATH,
        "approval state",
    )?;
    let review =
        parse_json_strict(&review_bytes).context("baseline review record is not strict JSON")?;
    let approval_state = parse_json_strict(&approval_state_bytes)
        .context("baseline approval state is not strict JSON")?;
    validate_signed_review_record(&review)?;
    validate_signed_approval_state(&approval_state)?;
    if review.get("schema").and_then(Value::as_str) != Some(REVIEW_SCHEMA) {
        bail!("baseline review record has the wrong schema");
    }
    if !matches!(
        approval_state.get("schema").and_then(Value::as_str),
        Some(APPROVAL_STATE_SCHEMA_V1 | APPROVAL_STATE_SCHEMA_V2 | APPROVAL_STATE_SCHEMA)
    ) {
        bail!("baseline approval state has the wrong schema");
    }
    for value in [&review, &approval_state] {
        if value.get("registry").and_then(Value::as_str)
            != Some(loaded.project.registry.id.as_str())
            || value.get("environment").and_then(Value::as_str) != Some(environment)
        {
            bail!("verified baseline is not bound to this registry and environment");
        }
    }
    if approval_state.get("compiler_version") != review.get("compiler_version") {
        bail!("verified baseline review and approval state disagree on compiler version");
    }
    let review_has_baseline =
        review.get("baseline").and_then(Value::as_str) == Some("verified_signed_bundle");
    let state_has_baseline = approval_state
        .get("baseline")
        .is_some_and(|baseline| !baseline.is_null());
    if review_has_baseline != state_has_baseline {
        bail!("verified baseline review and approval state disagree on baseline status");
    }
    if approval_state.get("report_digest").and_then(Value::as_str)
        != Some(sha256_uri(&review_bytes).as_str())
    {
        bail!("verified baseline approval state does not bind the signed review");
    }
    if approval_state.get("entity_materializations") != review.get("entity_materializations") {
        bail!("verified baseline review and approval state disagree on entity materializations");
    }
    let disclosure_profiles: DisclosureReviewProfiles = serde_json::from_value(
        review
            .get("disclosure_profiles")
            .cloned()
            .ok_or_else(|| anyhow!("baseline review record lacks disclosure_profiles"))?,
    )
    .context("baseline review disclosure_profiles are invalid")?;
    let disclosure_digest = digest_json(
        &serde_json::to_value(&disclosure_profiles)
            .context("failed to canonicalize baseline disclosure_profiles")?,
    )?;
    if approval_state
        .get("disclosure_digest")
        .and_then(Value::as_str)
        != Some(disclosure_digest.as_str())
    {
        bail!("verified baseline approval state does not bind the review disclosure profiles");
    }
    validate_verified_product_closure(&approval_state, &verified.manifest)?;
    Ok(Some(VerifiedBaseline {
        approval_state,
        approval_state_digest: sha256_uri(&approval_state_bytes),
        verified_manifest: serde_json::to_value(verified.manifest)
            .context("failed to retain verified baseline manifest identity")?,
        review_digest: sha256_uri(&review_bytes),
    }))
}

fn read_verified_bundle_payload(
    bundle: &Path,
    manifest: &registry_platform_config::ConfigBundleManifest,
    relative: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let path = bundle.join(relative);
    let bytes =
        fs::read(&path).with_context(|| format!("verified baseline lacks {}", path.display()))?;
    let digest = sha256_uri(&bytes);
    if manifest
        .files
        .iter()
        .find(|file| file.path == relative)
        .map(|file| file.sha256.as_str())
        != Some(digest.as_str())
    {
        bail!("verified baseline {label} changed after bundle verification");
    }
    Ok(bytes)
}

fn validate_verified_product_closure(
    approval_state: &Value,
    manifest: &registry_platform_config::ConfigBundleManifest,
) -> Result<()> {
    let product = match manifest.product.as_str() {
        "registry-relay" => "relay",
        "registry-notary" => "notary",
        _ => bail!("verified baseline manifest has an unsupported product"),
    };
    let expected = approval_state
        .pointer(&format!("/generated_closure_digests/{product}"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!("verified baseline approval state lacks its {product} closure digest")
        })?;
    let mut files = manifest
        .files
        .iter()
        .filter(|file| {
            !matches!(
                file.path.as_str(),
                APPROVAL_REVIEW_PATH | APPROVAL_STATE_PATH
            )
        })
        .map(|file| json!({ "path": file.path, "sha256": file.sha256 }))
        .collect::<Vec<_>>();
    files.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    if digest_json(&Value::Array(files))? != expected {
        bail!("verified baseline product closure does not match its signed approval state");
    }
    Ok(())
}

fn validate_signed_review_record(value: &Value) -> Result<()> {
    let review = exact_review_object(
        value,
        &[
            "schema",
            "registry",
            "compiler_version",
            "baseline",
            "disclosure_profiles",
            "semantic_changes",
            "environment",
            "entity_materializations",
            "consultations",
        ],
        "baseline review record",
    )?;
    for field in ["schema", "registry", "compiler_version", "environment"] {
        if review.get(field).and_then(Value::as_str).is_none() {
            bail!("baseline review record field {field} must be a string");
        }
    }
    if !matches!(
        review.get("baseline").and_then(Value::as_str),
        Some("initial_without_baseline" | "verified_signed_bundle")
    ) {
        bail!("baseline review record baseline status is invalid");
    }
    let profiles_value = review
        .get("disclosure_profiles")
        .ok_or_else(|| anyhow!("baseline review record lacks disclosure_profiles"))?;
    let _: DisclosureReviewProfiles = serde_json::from_value(profiles_value.clone())
        .context("baseline review disclosure_profiles are invalid")?;
    validate_semantic_changes(
        review
            .get("semantic_changes")
            .ok_or_else(|| anyhow!("baseline review record lacks semantic_changes"))?,
    )?;
    if !review
        .get("entity_materializations")
        .is_some_and(Value::is_object)
    {
        bail!("baseline review entity_materializations must be an object");
    }
    let consultations = review
        .get("consultations")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("baseline review consultations must be an object"))?;
    for consultation in consultations.values() {
        let consultation = exact_review_object(
            consultation,
            &["profile_id", "integration", "contract_hash"],
            "baseline review consultation",
        )?;
        for field in ["profile_id", "integration"] {
            if consultation.get(field).and_then(Value::as_str).is_none() {
                bail!("baseline review consultation field {field} must be a string");
            }
        }
        validate_review_sha256(consultation.get("contract_hash"), "contract_hash", false)?;
    }
    validate_public_report_hash_fields(value)?;
    Ok(())
}

fn validate_signed_approval_state(value: &Value) -> Result<()> {
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("baseline approval state schema must be a string"))?;
    let expected = match schema {
        APPROVAL_STATE_SCHEMA_V1 => &[
            "schema",
            "registry",
            "environment",
            "compiler_version",
            "report_digest",
            "authored_input_digest",
            "semantic_digests",
            "disclosure_digest",
            "generated_closure_digests",
            "baseline",
            "entity_materializations",
        ][..],
        APPROVAL_STATE_SCHEMA_V2 => &[
            "schema",
            "registry",
            "environment",
            "compiler_version",
            "report_digest",
            "authored_input_digest",
            "semantic_digests",
            "disclosure_digest",
            "promotion_projection",
            "generated_closure_digests",
            "baseline",
            "entity_materializations",
        ][..],
        APPROVAL_STATE_SCHEMA => &[
            "schema",
            "registry",
            "environment",
            "compiler_version",
            "report_digest",
            "authored_input_digest",
            "semantic_digests",
            "disclosure_digest",
            "promotion_projection",
            "generated_closure_digests",
            "baseline",
            "entity_materializations",
        ][..],
        _ => bail!("baseline approval state has the wrong schema"),
    };
    let state = exact_review_object(value, expected, "baseline approval state")?;
    for field in ["schema", "registry", "environment", "compiler_version"] {
        if state.get(field).and_then(Value::as_str).is_none() {
            bail!("baseline approval state field {field} must be a string");
        }
    }
    for field in [
        "report_digest",
        "authored_input_digest",
        "disclosure_digest",
    ] {
        validate_review_sha256(state.get(field), field, false)?;
    }
    let semantic = exact_review_object(
        state
            .get("semantic_digests")
            .ok_or_else(|| anyhow!("baseline approval state lacks semantic_digests"))?,
        &[
            "claim",
            "integration",
            "service_policy",
            "operator_security",
        ],
        "baseline approval semantic_digests",
    )?;
    for field in [
        "claim",
        "integration",
        "service_policy",
        "operator_security",
    ] {
        validate_review_sha256(semantic.get(field), field, false)?;
    }
    let promotion_products =
        if matches!(schema, APPROVAL_STATE_SCHEMA_V2 | APPROVAL_STATE_SCHEMA) {
            let promotion_projection: ProjectPromotionProjectionV1 =
                serde_json::from_value(state.get("promotion_projection").cloned().ok_or_else(
                    || anyhow!("baseline approval state lacks promotion_projection"),
                )?)
                .context("baseline approval promotion_projection is invalid")?;
            validate_project_promotion_projection_structure(&promotion_projection)
                .map_err(|error| anyhow!(error))?;
            Some(promotion_projection.products)
        } else {
            None
        };
    let closure = exact_review_object(
        state
            .get("generated_closure_digests")
            .ok_or_else(|| anyhow!("baseline approval state lacks generated_closure_digests"))?,
        &["reviewable", "relay", "notary"],
        "baseline approval generated_closure_digests",
    )?;
    validate_review_sha256(closure.get("reviewable"), "reviewable", false)?;
    for field in ["relay", "notary"] {
        if !closure.get(field).is_some_and(Value::is_null) {
            validate_review_sha256(closure.get(field), field, false)?;
        }
    }
    if let Some(products) = promotion_products.as_ref() {
        for (field, product) in [
            ("relay", PromotionProjectedProduct::Relay),
            ("notary", PromotionProjectedProduct::Notary),
        ] {
            let has_closure = closure.get(field).is_some_and(Value::is_string);
            if has_closure != products.contains(&product) {
                bail!(
                    "baseline approval promotion_projection product inventory disagrees with generated_closure_digests"
                );
            }
        }
    }
    validate_approval_baseline(
        state.get("baseline"),
        schema,
        state
            .get("environment")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("baseline approval state environment must be a string"))?,
        promotion_products.as_deref(),
    )?;
    if !state
        .get("entity_materializations")
        .is_some_and(Value::is_object)
    {
        bail!("baseline approval state entity_materializations must be an object");
    }
    Ok(())
}

fn validate_public_report_hash_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lower = key.to_ascii_lowercase();
                if (lower.contains("hash") || lower.contains("digest")) && key != "contract_hash" {
                    bail!("baseline review record exposes lower-level hash or digest field {key}");
                }
                validate_public_report_hash_fields(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_public_report_hash_fields(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn exact_review_object<'a>(
    value: &'a Value,
    expected: &[&str],
    label: &str,
) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{label} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{label} has missing or unknown fields");
    }
    Ok(object)
}

fn validate_review_sha256(value: Option<&Value>, field: &str, nullable: bool) -> Result<()> {
    let Some(value) = value else {
        bail!("baseline review record lacks {field}");
    };
    if nullable && value.is_null() {
        return Ok(());
    }
    let digest = value
        .as_str()
        .ok_or_else(|| anyhow!("baseline review field {field} must be a SHA-256 digest"))?;
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("baseline review field {field} must be a SHA-256 digest");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("baseline review field {field} must be a SHA-256 digest");
    }
    Ok(())
}

fn validate_semantic_changes(value: &Value) -> Result<()> {
    let changes = value
        .as_array()
        .ok_or_else(|| anyhow!("baseline semantic_changes must be an array"))?;
    let mut dimensions = BTreeSet::new();
    for change in changes {
        let change = exact_review_object(change, &["dimension"], "baseline semantic change")?;
        let dimension = change
            .get("dimension")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("baseline semantic change dimension must be a string"))?;
        if !matches!(
            dimension,
            "compiler"
                | "claim"
                | "integration"
                | "service_policy"
                | "operator_security"
                | "disclosure"
        ) || !dimensions.insert(dimension)
        {
            bail!("baseline semantic_changes contain an unknown or duplicate dimension");
        }
    }
    Ok(())
}

fn validate_approval_baseline(
    value: Option<&Value>,
    schema: &str,
    environment: &str,
    promotion_products: Option<&[PromotionProjectedProduct]>,
) -> Result<()> {
    let Some(value) = value else {
        bail!("baseline approval state lacks baseline");
    };
    if value.is_null() {
        return Ok(());
    }
    if schema == APPROVAL_STATE_SCHEMA {
        let baseline = exact_review_object(
            value,
            &["verified_manifests"],
            "baseline approval state baseline",
        )?;
        let manifests = exact_review_object(
            baseline
                .get("verified_manifests")
                .ok_or_else(|| anyhow!("baseline approval state lacks verified_manifests"))?,
            &["relay", "notary"],
            "baseline approval verified_manifests",
        )?;
        let mut present = 0_usize;
        for (field, expected_product, projected_product) in [
            ("relay", "registry-relay", PromotionProjectedProduct::Relay),
            (
                "notary",
                "registry-notary",
                PromotionProjectedProduct::Notary,
            ),
        ] {
            let Some(value) = manifests.get(field) else {
                bail!("baseline approval state lacks a product manifest identity");
            };
            if value.is_null() {
                continue;
            }
            let manifest: registry_platform_config::ConfigBundleManifest =
                serde_json::from_value(value.clone())
                    .context("baseline approval product manifest identity is invalid")?;
            manifest
                .validate()
                .context("baseline approval product manifest identity is invalid")?;
            if manifest.product != expected_product || manifest.environment != environment {
                bail!("baseline approval product manifest identity has the wrong product");
            }
            if !promotion_products.is_some_and(|products| products.contains(&projected_product)) {
                bail!("baseline approval product manifest identity is outside project topology");
            }
            present += 1;
        }
        if present == 0 {
            bail!("baseline approval state has no predecessor product manifest identity");
        }
        if promotion_products.is_some_and(|products| products.len() != present) {
            bail!("baseline approval product manifest identity set is incomplete");
        }
    } else {
        // v1 and v2 recorded one predecessor manifest because build accepted
        // only one unlabelled product baseline. Readers retain that exact
        // shape, while v3 writes the closed Relay/Notary identity set above.
        let baseline = exact_review_object(
            value,
            &["verified_manifest"],
            "baseline approval state baseline",
        )?;
        let manifest: registry_platform_config::ConfigBundleManifest = serde_json::from_value(
            baseline
                .get("verified_manifest")
                .cloned()
                .ok_or_else(|| anyhow!("baseline approval state lacks verified_manifest"))?,
        )
        .context("baseline approval verified_manifest is invalid")?;
        manifest
            .validate()
            .context("baseline approval verified_manifest is invalid")?;
        if manifest.environment != environment {
            bail!("baseline approval verified_manifest has the wrong environment");
        }
    }
    Ok(())
}

fn semantic_change_records(
    loaded: &LoadedRegistryProject,
    baseline: Option<&Value>,
    disclosure_digest: &str,
) -> Vec<SemanticChange> {
    let mut changes = [
        (
            "claim",
            loaded.semantic_digests.claim.as_str(),
            baseline
                .and_then(|review| review.get("semantic_digests"))
                .and_then(|digests| digests.get("claim"))
                .and_then(Value::as_str),
        ),
        (
            "integration",
            loaded.semantic_digests.integration.as_str(),
            baseline
                .and_then(|review| review.get("semantic_digests"))
                .and_then(|digests| digests.get("integration"))
                .and_then(Value::as_str),
        ),
        (
            "service_policy",
            loaded.semantic_digests.service_policy.as_str(),
            baseline
                .and_then(|review| review.get("semantic_digests"))
                .and_then(|digests| digests.get("service_policy"))
                .and_then(Value::as_str),
        ),
        (
            "operator_security",
            loaded.semantic_digests.operator_security.as_str(),
            baseline
                .and_then(|review| review.get("semantic_digests"))
                .and_then(|digests| digests.get("operator_security"))
                .and_then(Value::as_str),
        ),
        (
            "disclosure",
            disclosure_digest,
            baseline
                .and_then(|review| review.get("disclosure_digest"))
                .and_then(Value::as_str),
        ),
    ]
    .into_iter()
    .filter(|(_, current, previous)| *previous != Some(*current))
    .map(|(dimension, _, _)| SemanticChange { dimension })
    .collect::<Vec<_>>();
    if baseline
        .and_then(|review| review.get("compiler_version"))
        .and_then(Value::as_str)
        .is_some_and(|version| version != env!("CARGO_PKG_VERSION"))
    {
        changes.push(SemanticChange {
            dimension: "compiler",
        });
    }
    changes
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to stat project {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("project root must be a real directory");
    }
    root.canonicalize()
        .with_context(|| format!("failed to canonicalize {}", root.display()))
}

fn resolve_authored_path(root: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_authored_path(relative)?;
    let path = root.join(relative);
    reject_symlink_components(root, &path)?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve authored file {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("authored file escapes the project root");
    }
    Ok(canonical)
}

fn resolve_relative_to_file(root: &Path, file: &Path, relative: &Path) -> Result<PathBuf> {
    validate_relative_authored_path(relative)?;
    let parent = file
        .parent()
        .ok_or_else(|| anyhow!("authored file has no parent"))?;
    let path = parent.join(relative);
    reject_symlink_components(root, &path)?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))?;
    if !canonical.starts_with(root) {
        bail!("authored reference escapes the project root");
    }
    Ok(canonical)
}

fn validate_relative_authored_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("authored paths must be non-empty and relative");
    }
    for component in path.components() {
        match component {
            Component::Normal(part) if !part.is_empty() => {}
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                bail!("authored paths must be normalized and cannot traverse")
            }
            Component::Normal(_) => bail!("authored path component is empty"),
        }
    }
    Ok(())
}

fn reject_symlink_components(root: &Path, path: &Path) -> Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path is outside project root"))?;
    let mut current = root.to_path_buf();
    reject_symlink(&current)?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("path is not normalized");
        };
        current.push(component);
        if current.exists() {
            reject_symlink(&current)?;
        }
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("symlinks are forbidden at the project authoring boundary");
    }
    Ok(())
}

fn read_authored_file(root: &Path, path: &Path) -> Result<Vec<u8>> {
    reject_symlink_components(root, path)?;
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_AUTHORED_FILE_BYTES {
        bail!("authored file must be a bounded regular file");
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > MAX_AUTHORED_FILE_BYTES {
        bail!("authored file exceeds the size bound");
    }
    Ok(bytes)
}

fn load_fixtures(
    root: &Path,
    directory: &Path,
    hasher: &mut Sha256,
    artifact_inputs: &mut BTreeMap<String, ArtifactInputDigest>,
) -> Result<Vec<(PathBuf, FixtureDocument)>> {
    const MAX_FIXTURE_BODY_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_FIXTURE_BODY_CLOSURE_BYTES: u64 = 16 * 1024 * 1024;

    reject_symlink_components(root, directory)?;
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("failed to stat fixture directory {}", directory.display()))?;
    if !metadata.is_dir() {
        bail!("fixture path must be a directory");
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to read fixture directory {}", directory.display()))?
    {
        let entry = entry.context("failed to read fixture directory entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat fixture {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("fixture directories and bodies may not contain symlinks");
        }
        if metadata.is_dir() {
            if path.file_name().and_then(|value| value.to_str()) == Some("bodies") {
                continue;
            }
            bail!("fixture directories may contain only direct YAML files and bodies/");
        }
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            bail!("fixture directory contains an unsupported file");
        }
        paths.push(path);
    }
    paths.sort_by(|left, right| {
        left.file_name()
            .map(std::ffi::OsStr::as_encoded_bytes)
            .cmp(&right.file_name().map(std::ffi::OsStr::as_encoded_bytes))
    });
    if paths.is_empty() || paths.len() > MAX_FIXTURES {
        bail!("integration must contain between one and 128 fixtures");
    }
    let mut body_cache = BTreeMap::<PathBuf, Value>::new();
    let mut fixtures = paths
        .into_iter()
        .map(|path| {
            let bytes = read_authored_file(root, &path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("fixture escapes project root"))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| anyhow!("fixture path is not Unicode"))?;
            record_artifact_input(artifact_inputs, relative, &bytes)?;
            hash_authored_file(hasher, relative, &bytes);
            let authored: AuthoredFixtureDocument = parse_yaml(&bytes, relative)?;
            let fixture = lower_authored_fixture(
                root,
                directory,
                authored,
                &mut body_cache,
                MAX_FIXTURE_BODY_BYTES,
            )?;
            Ok((path, fixture))
        })
        .collect::<Result<Vec<_>>>()?;
    let closure_bytes = body_cache.keys().try_fold(0_u64, |total, path| {
        let metadata = fs::metadata(path)
            .with_context(|| format!("failed to stat fixture body {}", path.display()))?;
        total
            .checked_add(metadata.len())
            .ok_or_else(|| anyhow!("fixture body closure exceeds its size bound"))
    })?;
    if closure_bytes > MAX_FIXTURE_BODY_CLOSURE_BYTES {
        bail!("fixture body closure exceeds the 16 MiB bound");
    }
    for path in body_cache.keys() {
        let bytes = read_bounded_fixture_body(root, path, MAX_FIXTURE_BODY_BYTES)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow!("fixture body escapes project root"))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| anyhow!("fixture body path is not Unicode"))?;
        record_artifact_input(artifact_inputs, relative, &bytes)?;
        hash_authored_file(hasher, relative, &bytes);
    }
    fixtures.sort_by(|left, right| left.1.name.as_bytes().cmp(right.1.name.as_bytes()));
    Ok(fixtures)
}

fn lower_authored_fixture(
    root: &Path,
    fixture_directory: &Path,
    authored: AuthoredFixtureDocument,
    body_cache: &mut BTreeMap<PathBuf, Value>,
    max_body_bytes: u64,
) -> Result<FixtureDocument> {
    if let Some(request) = authored.request.as_ref() {
        if authored.classification != AuthoredFixtureClassification::Synthetic {
            bail!("fixture governed requests require classification: synthetic");
        }
        let request = serde_json::to_value(request)
            .context("failed to inspect the governed synthetic fixture request")?;
        if contains_sensitive_request_key(&request) || contains_fixture_secret_reference(&request) {
            bail!("fixture governed request contains a forbidden credential-like field");
        }
    }
    let interactions = authored
        .interactions
        .into_iter()
        .map(|interaction| {
            let expected_body = interaction
                .expect
                .body
                .map(|body| {
                    resolve_fixture_body(root, fixture_directory, body, body_cache, max_body_bytes)
                })
                .transpose()?;
            let respond = match interaction.respond {
                AuthoredFixtureResponse::Http(AuthoredFixtureHttpResponse {
                    status,
                    headers,
                    body,
                }) => FixtureSourceResponse::Http {
                    status,
                    headers,
                    body: body
                        .map(|body| {
                            resolve_fixture_body(
                                root,
                                fixture_directory,
                                body,
                                body_cache,
                                max_body_bytes,
                            )
                        })
                        .transpose()?
                        .unwrap_or(Value::Null),
                },
                AuthoredFixtureResponse::Timeout(AuthoredFixtureTimeoutResponse { timeout }) => {
                    FixtureSourceResponse::Timeout { timeout }
                }
            };
            Ok(FixtureInteraction {
                expect: FixtureRequestExpectation {
                    method: interaction.expect.method,
                    path: interaction.expect.path,
                    query: interaction.expect.query,
                    headers: interaction.expect.headers,
                    body: expected_body,
                },
                respond,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FixtureDocument {
        name: authored.name,
        classification: authored.classification,
        request: authored.request,
        input: authored.input,
        variables: authored.variables,
        interactions,
        expect: authored.expect,
    })
}

fn contains_fixture_secret_reference(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            value.starts_with("${")
                || lower.starts_with("secret://")
                || lower.starts_with("env://")
                || lower.starts_with("vault://")
        }
        Value::Array(values) => values.iter().any(contains_fixture_secret_reference),
        Value::Object(object) => object.values().any(contains_fixture_secret_reference),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn resolve_fixture_body(
    root: &Path,
    fixture_directory: &Path,
    body: AuthoredFixtureBody,
    body_cache: &mut BTreeMap<PathBuf, Value>,
    max_body_bytes: u64,
) -> Result<Value> {
    match body {
        AuthoredFixtureBody::Inline(value) => Ok(value),
        AuthoredFixtureBody::File(AuthoredFixtureBodyFile { file }) => {
            let mut components = file.components();
            if components.next() != Some(Component::Normal(std::ffi::OsStr::new("bodies")))
                || components.next().is_none()
                || components.any(|component| !matches!(component, Component::Normal(_)))
            {
                bail!("fixture body file must be a normalized bodies/<file> path");
            }
            let path = fixture_directory.join(&file);
            reject_symlink_components(root, &path)?;
            if let Some(value) = body_cache.get(&path) {
                return Ok(value.clone());
            }
            let bytes = read_bounded_fixture_body(root, &path, max_body_bytes)?;
            let value = parse_json_strict(&bytes)
                .map_err(|_| anyhow!("fixture body file must contain strict JSON"))?;
            body_cache.insert(path, value.clone());
            Ok(value)
        }
    }
}

fn read_bounded_fixture_body(root: &Path, path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    reject_symlink_components(root, path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to stat fixture body {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        bail!("fixture body must be a bounded regular non-symlink file");
    }
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open fixture body {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read fixture body {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        bail!("fixture body exceeds the 8 MiB bound");
    }
    Ok(bytes)
}

fn parse_yaml<T: CurrentAuthoringDocument>(bytes: &[u8], label: &str) -> Result<T> {
    parse_current_authoring_document(bytes).map_err(|error| {
        anyhow!(
            "{label}: {error}; schema hint: registryctl authoring schema --kind {} > {}.schema.json",
            T::KIND.name(),
            T::KIND.name(),
        )
    })
}

fn hash_authored_file(hasher: &mut Sha256, relative: &str, bytes: &[u8]) {
    hasher.update((relative.len() as u64).to_be_bytes());
    hasher.update(relative.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn create_dir_owner_only(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    Ok(())
}

fn validate_stable_id(value: &str, field: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 96
        || !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        bail!("{field} must match the bounded stable-id grammar");
    }
    Ok(())
}

fn validate_input_name(value: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 64
        || !matches!(bytes.next(), Some(b'a'..=b'z'))
        || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
    {
        bail!("integration input name must match [a-z][a-z0-9_]{{0,63}}");
    }
    Ok(())
}

fn validate_token(value: &str, field: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.contains(',')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("{field} must be one bounded token");
    }
    Ok(())
}

fn validate_header_token(value: &str, field: &str, max_bytes: usize) -> Result<()> {
    validate_token(value, field, max_bytes)?;
    if !value.is_ascii() {
        bail!("{field} must use visible ASCII");
    }
    Ok(())
}

fn validate_release_version(value: &str, field: &str) -> Result<()> {
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 64
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
        || !bytes.all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
    {
        bail!("{field} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,63}}");
    }
    Ok(())
}

fn validate_scopes(scopes: &[String]) -> Result<()> {
    if scopes.is_empty() || scopes.len() > 16 {
        bail!("caller scopes must contain between one and 16 entries");
    }
    let mut unique = BTreeSet::new();
    for scope in scopes {
        validate_token(scope, "scope", 128)?;
        if !unique.insert(scope) {
            bail!("caller scopes contain a duplicate");
        }
    }
    Ok(())
}

fn validate_request_mapping(mapping: &str) -> Result<()> {
    if mapping == "request.target.id" {
        return Ok(());
    }
    if let Some(attribute) = mapping.strip_prefix("request.target.attributes.") {
        let mut bytes = attribute.bytes();
        if attribute.is_empty()
            || attribute.len() > 64
            || !matches!(bytes.next(), Some(b'a'..=b'z'))
            || !bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        {
            bail!("target attribute must match [a-z][a-z0-9_]{{0,63}}");
        }
        return Ok(());
    }
    let identifier = mapping
        .strip_prefix("request.target.identifiers.")
        .ok_or_else(|| anyhow!("consultation input must use the closed target grammar"))?;
    let mut bytes = identifier.bytes();
    if identifier.is_empty()
        || identifier.len() > 96
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z'))
        || !bytes.all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
        )
    {
        bail!("target identifier must match the bounded identifier grammar");
    }
    Ok(())
}

fn validate_disclosure(disclosure: &DisclosureDeclaration) -> Result<()> {
    match disclosure {
        DisclosureDeclaration::Mode(_) => Ok(()),
        DisclosureDeclaration::Policy { default, allowed } => {
            if allowed.is_empty() || !allowed.contains(default) {
                bail!("disclosure policy must allow its default mode");
            }
            let unique = allowed.iter().copied().collect::<BTreeSet<_>>();
            if unique.len() != allowed.len() {
                bail!("disclosure allowed modes contain duplicates");
            }
            Ok(())
        }
    }
}

fn validate_secret_reference(reference: &SecretReference) -> Result<()> {
    let value = reference.secret.as_str();
    let mut bytes = value.bytes();
    if value.is_empty()
        || value.len() > 128
        || !matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
        || !bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
    {
        bail!("secret references must be bounded environment identifiers");
    }
    Ok(())
}

fn validate_https_origin(value: &str, field: &str) -> Result<()> {
    let origin = url::Url::parse(value).with_context(|| format!("{field} is not a URL"))?;
    if origin.scheme() != "https"
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("{field} must be an exact HTTPS origin");
    }
    Ok(())
}

fn validate_https_or_local_loopback_origin(
    value: &str,
    field: &str,
    allow_local_loopback: bool,
) -> Result<()> {
    let origin = url::Url::parse(value).with_context(|| format!("{field} is not a URL"))?;
    let secure = origin.scheme() == "https";
    let local_loopback =
        allow_local_loopback && origin.scheme() == "http" && url_host_is_ip_loopback(&origin);
    if (!secure && !local_loopback)
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!(
            "{field} must be an exact HTTPS origin or an HTTP IP-loopback origin in a local environment"
        );
    }
    Ok(())
}

fn validate_internal_https_or_loopback_origin(value: &str, field: &str) -> Result<()> {
    let origin = url::Url::parse(value).with_context(|| format!("{field} is not a URL"))?;
    let secure = origin.scheme() == "https";
    let local_loopback = origin.scheme() == "http" && url_host_is_ip_loopback(&origin);
    if (!secure && !local_loopback)
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("{field} must be an exact HTTPS origin or HTTP IP-loopback origin");
    }
    Ok(())
}

fn validate_https_or_local_loopback_resource(
    value: &str,
    field: &str,
    allow_local_loopback: bool,
) -> Result<()> {
    let resource = url::Url::parse(value).with_context(|| format!("{field} is invalid"))?;
    let secure = resource.scheme() == "https";
    let local_loopback =
        allow_local_loopback && resource.scheme() == "http" && url_host_is_ip_loopback(&resource);
    if (!secure && !local_loopback)
        || resource.host().is_none()
        || !resource.username().is_empty()
        || resource.password().is_some()
        || resource.path() == "/"
        || resource.query().is_some()
        || resource.fragment().is_some()
    {
        bail!(
            "{field} must be one exact HTTPS resource or an HTTP IP-loopback resource in a local environment"
        );
    }
    Ok(())
}

fn url_host_is_ip_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    }
}

fn url_uses_http(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| url.scheme() == "http")
}

fn normalize_url_scheme(value: &str) -> Result<String> {
    let url = url::Url::parse(value).context("validated environment URL no longer parses")?;
    let (_, suffix) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("validated environment URL has no scheme separator"))?;
    Ok(format!("{}:{suffix}", url.scheme()))
}

fn validate_absolute_runtime_path(path: &Path, field: &str) -> Result<()> {
    let value = path
        .to_str()
        .ok_or_else(|| anyhow!("{field} must be valid UTF-8"))?;
    if value.len() > 4096 || !value.starts_with('/') {
        bail!("{field} must be one bounded absolute path");
    }
    if value == "/"
        || value.starts_with("//")
        || value.ends_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("{field} must be normalized and cannot traverse");
    }
    Ok(())
}

fn validate_full_date(value: &str) -> Result<()> {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        bail!("date must use RFC 3339 full-date syntax");
    }
    let year = value[0..4].parse::<i32>()?;
    let month = value[5..7].parse::<u8>()?;
    let day = value[8..10].parse::<u8>()?;
    time::Date::from_calendar_date(
        year,
        time::Month::try_from(month).map_err(|_| anyhow!("date month is invalid"))?,
        day,
    )
    .context("date is invalid")?;
    Ok(())
}

fn canonical_json_line(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = canonicalize_json(value).context("failed to canonicalize generated JSON")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod runtime_path_tests {
    use super::*;

    #[test]
    fn runtime_paths_use_target_posix_semantics_on_every_authoring_host() {
        assert!(validate_absolute_runtime_path(
            Path::new("/run/secrets/relay-workload-token"),
            "runtime path"
        )
        .is_ok());
    }

    #[test]
    fn runtime_paths_reject_relative_ambiguous_and_traversing_forms() {
        for value in [
            "run/secrets/token",
            "/",
            "//run/secrets/token",
            "/run/secrets/token/",
            "/run/./secrets/token",
            "/run/../secrets/token",
            "/run\\secrets\\token",
            "C:\\run\\secrets\\token",
        ] {
            assert!(
                validate_absolute_runtime_path(Path::new(value), "runtime path").is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }
}

#[cfg(test)]
mod fixture_body_security_tests {
    use super::*;

    fn temporary_root() -> PathBuf {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).expect("temporary root randomness");
        let root = std::env::temp_dir().join(format!(
            "registryctl-fixture-body-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        fs::create_dir_all(root.join("integrations/example/fixtures/bodies"))
            .expect("fixture body directory");
        root
    }

    #[test]
    fn fixture_body_reference_is_confined_to_bodies_subtree() {
        let root = temporary_root();
        let fixture_directory = root.join("integrations/example/fixtures");
        let mut cache = BTreeMap::new();
        let result = resolve_fixture_body(
            &root,
            &fixture_directory,
            AuthoredFixtureBody::File(AuthoredFixtureBodyFile {
                file: PathBuf::from("../outside.json"),
            }),
            &mut cache,
            8 * 1024 * 1024,
        );
        assert!(result.is_err());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[test]
    fn fixture_body_bound_is_checked_before_reading() {
        let root = temporary_root();
        let path = root.join("integrations/example/fixtures/bodies/large.json");
        let file = fs::File::create(&path).expect("large fixture body");
        file.set_len(8 * 1024 * 1024 + 1)
            .expect("set fixture body length");
        assert!(read_bounded_fixture_body(&root, &path, 8 * 1024 * 1024).is_err());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    #[cfg(unix)]
    #[test]
    fn fixture_body_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = temporary_root();
        let bodies = root.join("integrations/example/fixtures/bodies");
        let target = bodies.join("target.json");
        fs::write(&target, b"{}\n").expect("target body");
        let link = bodies.join("link.json");
        symlink(&target, &link).expect("fixture body symlink");
        assert!(read_bounded_fixture_body(&root, &link, 8 * 1024 * 1024).is_err());
        fs::remove_dir_all(root).expect("remove fixture root");
    }
}
