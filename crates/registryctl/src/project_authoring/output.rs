// SPDX-License-Identifier: Apache-2.0

fn validate_generated_product_configs(compiled: &CompiledProject) -> Result<()> {
    if compiled.relay_private.is_empty() && compiled.notary_private.is_empty() {
        bail!("generated deployment has no product configuration");
    }
    if !compiled.relay_private.is_empty() {
        let relay_config = compiled
            .relay_private
            .get(Path::new("config/relay.yaml"))
            .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
        validate_generated_relay(relay_config, &compiled.relay_private)?;
    }
    if !compiled.notary_private.is_empty() {
        validate_generated_notary(compiled)?;
    }
    Ok(())
}

fn validate_generated_notary(compiled: &CompiledProject) -> Result<()> {
    let notary_config = compiled
        .notary_private
        .get(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated Notary config is absent"))?;
    let notary: StandaloneRegistryNotaryConfig =
        serde_yaml::from_slice(notary_config).context("generated Notary config did not parse")?;
    notary
        .validate()
        .context("generated Notary config failed the production validator")?;
    Ok(())
}

fn validate_generated_relay(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<()> {
    validate_generated_relay_activation(relay_config, files)?;
    let config: Value = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse as strict YAML")?;
    if config
        .pointer("/consultation/artifacts/public_contracts")
        .and_then(Value::as_array)
        .is_some_and(|contracts| !contracts.is_empty())
    {
        compile_generated_relay_fixture(relay_config, files).map(drop)?;
    }
    Ok(())
}

fn validate_generated_relay_activation(
    relay_config: &[u8],
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<()> {
    let validation_root = GeneratedValidationDirectory::create()?;
    write_file_map(&validation_root.path, files)?;
    let config_path = validation_root.path.join("config/relay.yaml");
    let mut local_config: Value = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse for activation validation")?;
    local_config["deployment"]["profile"] = Value::String("local".to_string());
    fs::remove_file(&config_path)
        .context("failed to stage generated Relay activation validation")?;
    write_private_file(
        &config_path,
        serde_yaml::to_string(&local_config)?.as_bytes(),
    )?;
    let mut loaded = registry_relay::config::load_with_metadata(&config_path)
        .map_err(|error| anyhow!("generated Relay config failed production loading: {error:?}"))?;
    if let Some(artifacts) = loaded.consultation_artifacts.take() {
        registry_relay::consultation::ConsultationService::validate_configuration(
            &loaded.runtime,
            artifacts,
        )
        .context("generated Relay config failed production consultation activation validation")?;
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
) -> Result<registry_relay::offline_fixture::OfflineRelayFixture> {
    let runtime: registry_relay::config::Config = serde_yaml::from_slice(relay_config)
        .context("generated Relay config did not parse with the production model")?;
    registry_relay::config::validate::run(&runtime).map_err(|error| {
        anyhow!("generated Relay config failed the production startup validator: {error:?}")
    })?;
    let config: Value = serde_yaml::from_slice(relay_config)
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
    registry_relay::offline_fixture::OfflineRelayFixture::compile_with_worker_program(
        &bundle,
        project_registryctl_program()?,
    )
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
) -> Result<()> {
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
        write_private_file(
            &relay_root.join(APPROVAL_STATE_PATH),
            &approval_state_bytes,
        )?;
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
    Ok(())
}

#[cfg(unix)]
fn assign_unpublished_runtime_input_owner(
    path: &Path,
    identity: crate::RuntimeIdentity,
) -> Result<()> {
    use std::os::unix::fs::{lchown, MetadataExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect unpublished runtime input {}", path.display()))?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        bail!(
            "unpublished runtime input contains an unsupported file type: {}",
            path.display()
        );
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to read unpublished runtime input {}", path.display()))?
        {
            let child = entry
                .with_context(|| {
                    format!("failed to read an entry under unpublished runtime input {}", path.display())
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
    let review_bytes = read_verified_bundle_payload(
        bundle,
        &verified.manifest,
        APPROVAL_REVIEW_PATH,
        "review",
    )?;
    let approval_state_bytes = read_verified_bundle_payload(
        bundle,
        &verified.manifest,
        APPROVAL_STATE_PATH,
        "approval state",
    )?;
    let review = parse_json_strict(&review_bytes)
        .context("baseline review record is not strict JSON")?;
    let approval_state = parse_json_strict(&approval_state_bytes)
        .context("baseline approval state is not strict JSON")?;
    validate_signed_review_record(&review)?;
    validate_signed_approval_state(&approval_state)?;
    if review.get("schema").and_then(Value::as_str) != Some(REVIEW_SCHEMA) {
        bail!("baseline review record has the wrong schema");
    }
    if approval_state.get("schema").and_then(Value::as_str) != Some(APPROVAL_STATE_SCHEMA) {
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
    let review_has_baseline = review.get("baseline").and_then(Value::as_str)
        == Some("verified_signed_bundle");
    let state_has_baseline = approval_state
        .get("baseline")
        .is_some_and(|baseline| !baseline.is_null());
    if review_has_baseline != state_has_baseline {
        bail!("verified baseline review and approval state disagree on baseline status");
    }
    if approval_state
        .get("report_digest")
        .and_then(Value::as_str)
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
        verified_manifest: serde_json::to_value(verified.manifest)
            .context("failed to retain verified baseline manifest identity")?,
    }))
}

fn read_verified_bundle_payload(
    bundle: &Path,
    manifest: &registry_platform_config::ConfigBundleManifest,
    relative: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let path = bundle.join(relative);
    let bytes = fs::read(&path)
        .with_context(|| format!("verified baseline lacks {}", path.display()))?;
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
        .ok_or_else(|| anyhow!("verified baseline approval state lacks its {product} closure digest"))?;
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
    let state = exact_review_object(
        value,
        &[
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
        ],
        "baseline approval state",
    )?;
    for field in ["schema", "registry", "environment", "compiler_version"] {
        if state.get(field).and_then(Value::as_str).is_none() {
            bail!("baseline approval state field {field} must be a string");
        }
    }
    for field in ["report_digest", "authored_input_digest", "disclosure_digest"] {
        validate_review_sha256(state.get(field), field, false)?;
    }
    let semantic = exact_review_object(
        state
            .get("semantic_digests")
            .ok_or_else(|| anyhow!("baseline approval state lacks semantic_digests"))?,
        &["claim", "integration", "service_policy", "operator_security"],
        "baseline approval semantic_digests",
    )?;
    for field in ["claim", "integration", "service_policy", "operator_security"] {
        validate_review_sha256(semantic.get(field), field, false)?;
    }
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
    validate_approval_baseline(state.get("baseline"))?;
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
        let change = exact_review_object(
            change,
            &["dimension"],
            "baseline semantic change",
        )?;
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

fn validate_approval_baseline(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        bail!("baseline approval state lacks baseline");
    };
    if value.is_null() {
        return Ok(());
    }
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
            hash_authored_file(
                hasher,
                relative
                    .to_str()
                    .ok_or_else(|| anyhow!("fixture path is not Unicode"))?,
                &bytes,
            );
            let authored: AuthoredFixtureDocument =
                parse_yaml(&bytes, &relative.display().to_string())?;
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
        hash_authored_file(
            hasher,
            relative
                .to_str()
                .ok_or_else(|| anyhow!("fixture body path is not Unicode"))?,
            &bytes,
        );
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
                AuthoredFixtureResponse::Http {
                    status,
                    headers,
                    body,
                } => FixtureSourceResponse::Http {
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
                AuthoredFixtureResponse::Timeout { timeout } => {
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
        input: authored.input,
        variables: authored.variables,
        interactions,
        expect: authored.expect,
    })
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
        AuthoredFixtureBody::File { file } => {
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

fn parse_yaml<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_yaml::from_slice(bytes).map_err(|error| {
        let location = error
            .location()
            .map(|location| format!(":{}:{}", location.line(), location.column()))
            .unwrap_or_default();
        let schema = authored_schema_kind(label)
            .map(|kind| {
                format!(
                    "; schema hint: registryctl authoring schema --kind {kind} > {kind}.schema.json"
                )
            })
            .unwrap_or_default();
        anyhow!("{label}{location}: invalid authored YAML: {error}{schema}")
    })
}

fn authored_schema_kind(label: &str) -> Option<&'static str> {
    let normalized = label.replace('\\', "/");
    if normalized == PROJECT_FILE || normalized.ends_with("/registry-stack.yaml") {
        Some("project")
    } else if normalized.contains("/environments/") || normalized.starts_with("environments/") {
        Some("environment")
    } else if normalized.ends_with("/integration.yaml") {
        Some("integration")
    } else if normalized.contains("/fixtures/") || normalized.starts_with("fixtures/") {
        Some("fixture")
    } else if normalized.contains("/entities/") || normalized.starts_with("entities/") {
        Some("entity")
    } else {
        None
    }
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
    let local_loopback = allow_local_loopback
        && origin.scheme() == "http"
        && url_host_is_ip_loopback(&origin);
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
    let local_loopback = allow_local_loopback
        && resource.scheme() == "http"
        && url_host_is_ip_loopback(&resource);
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

fn parse_duration_ms(value: &str) -> Result<u32> {
    parse_duration_ms_with_max(value, 20_000, "deadline")
}

fn parse_materialization_refresh_ms(value: &str) -> Result<u32> {
    parse_duration_ms_with_max(
        value,
        30 * 24 * 60 * 60 * 1_000,
        "entity materialization refresh",
    )
}

fn parse_duration_ms_with_max(value: &str, maximum: u32, label: &str) -> Result<u32> {
    let milliseconds = if let Some(milliseconds) = value.strip_suffix("ms") {
        Some(milliseconds.parse::<u32>()?)
    } else if let Some(seconds) = value.strip_suffix('s') {
        seconds.parse::<u32>()?.checked_mul(1_000)
    } else if let Some(minutes) = value.strip_suffix('m') {
        minutes.parse::<u32>()?.checked_mul(60_000)
    } else if let Some(hours) = value.strip_suffix('h') {
        hours.parse::<u32>()?.checked_mul(60 * 60 * 1_000)
    } else if let Some(days) = value.strip_suffix('d') {
        days.parse::<u32>()?.checked_mul(24 * 60 * 60 * 1_000)
    } else {
        None
    }
    .ok_or_else(|| anyhow!("{label} must be a bounded positive duration"))?;
    if milliseconds == 0 || milliseconds > maximum {
        bail!("{label} is outside its reviewed bound");
    }
    Ok(milliseconds)
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
            AuthoredFixtureBody::File {
                file: PathBuf::from("../outside.json"),
            },
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
