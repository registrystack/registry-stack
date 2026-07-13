// SPDX-License-Identifier: Apache-2.0

fn validate_generated_product_configs(compiled: &CompiledCountry) -> Result<()> {
    let relay_config = compiled
        .relay_private
        .get(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated Relay config is absent"))?;
    validate_generated_relay(relay_config, &compiled.relay_private)?;
    validate_generated_notary(compiled)
}

fn validate_generated_notary(compiled: &CompiledCountry) -> Result<()> {
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
    compile_generated_relay_fixture(relay_config, files).map(drop)
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
        .map_err(|_| anyhow!("generated Relay config failed production loading"))?;
    let artifacts = loaded
        .consultation_artifacts
        .take()
        .ok_or_else(|| anyhow!("generated Relay consultation artifacts were not loaded"))?;
    registry_relay::consultation::ConsultationService::validate_configuration(
        &loaded.runtime,
        artifacts,
    )
    .context("generated Relay config failed production consultation activation validation")
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
                "registryctl-country-validation-{}-{}",
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
    registry_relay::offline_fixture::OfflineRelayFixture::compile(&bundle)
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

fn write_compiled_country(root: &Path, output: &Path, compiled: &CompiledCountry) -> Result<()> {
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
    let relay_root = temporary.join("private/relay");
    let notary_root = temporary.join("private/notary");
    create_dir_owner_only(&reviewable_root)?;
    create_dir_owner_only(&relay_root)?;
    create_dir_owner_only(&notary_root)?;
    write_file_map(&reviewable_root, &compiled.reviewable)?;
    write_file_map(&relay_root, &compiled.relay_private)?;
    write_file_map(&notary_root, &compiled.notary_private)?;
    let review_bytes = canonical_json_line(&compiled.review)?;
    write_private_file(&reviewable_root.join("review.json"), &review_bytes)?;
    write_private_file(&relay_root.join("approval/review.json"), &review_bytes)?;
    write_private_file(&notary_root.join("approval/review.json"), &review_bytes)?;

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
    loaded: &LoadedCountryProject,
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
    let review_path = bundle.join("approval/review.json");
    let bytes = fs::read(&review_path)
        .with_context(|| format!("verified baseline lacks {}", review_path.display()))?;
    let review_hash = sha256_uri(&bytes);
    if verified
        .manifest
        .files
        .iter()
        .find(|file| file.path == "approval/review.json")
        .map(|file| file.sha256.as_str())
        != Some(review_hash.as_str())
    {
        bail!("verified baseline review changed after bundle verification");
    }
    let value = parse_json_strict(&bytes).context("baseline review record is not strict JSON")?;
    validate_signed_review_record(&value)?;
    if value.get("schema").and_then(Value::as_str) != Some(REVIEW_SCHEMA) {
        bail!("baseline review record has the wrong schema");
    }
    if value.get("registry").and_then(Value::as_str) != Some(loaded.project.registry.id.as_str())
        || value.get("environment").and_then(Value::as_str) != Some(environment)
    {
        bail!("verified baseline review is not bound to this registry and environment");
    }
    Ok(Some(VerifiedBaseline {
        review: value,
        verified_manifest: serde_json::to_value(verified.manifest)
            .context("failed to retain verified baseline manifest identity")?,
    }))
}

fn validate_signed_review_record(value: &Value) -> Result<()> {
    let review = exact_review_object(
        value,
        &[
            "schema",
            "registry",
            "source_revision",
            "compiler_version",
            "baseline",
            "authored_input_digest",
            "semantic_digests",
            "disclosure_profiles",
            "disclosure_digest",
            "generated_closure_digests",
            "semantic_changes",
            "required_reviews",
            "review_digests",
            "environment",
            "entity_materializations",
        ],
        "baseline review record",
    )?;
    for field in ["schema", "registry", "compiler_version", "environment"] {
        if review.get(field).and_then(Value::as_str).is_none() {
            bail!("baseline review record field {field} must be a string");
        }
    }
    for field in ["source_revision", "authored_input_digest", "disclosure_digest"] {
        validate_review_sha256(review.get(field), field, false)?;
    }

    let semantic = exact_review_object(
        review
            .get("semantic_digests")
            .ok_or_else(|| anyhow!("baseline review record lacks semantic_digests"))?,
        &["claim", "integration", "country_policy", "operator_security"],
        "baseline semantic_digests",
    )?;
    for field in ["claim", "integration", "country_policy", "operator_security"] {
        validate_review_sha256(semantic.get(field), field, false)?;
    }

    let closure = exact_review_object(
        review
            .get("generated_closure_digests")
            .ok_or_else(|| anyhow!("baseline review record lacks generated_closure_digests"))?,
        &["reviewable", "relay", "notary"],
        "baseline generated_closure_digests",
    )?;
    for field in ["reviewable", "relay", "notary"] {
        validate_review_sha256(closure.get(field), field, false)?;
    }

    let profiles_value = review
        .get("disclosure_profiles")
        .ok_or_else(|| anyhow!("baseline review record lacks disclosure_profiles"))?;
    let profiles: DisclosureReviewProfiles = serde_json::from_value(profiles_value.clone())
        .context("baseline review disclosure_profiles are invalid")?;
    let computed_disclosure_digest = digest_json(
        &serde_json::to_value(&profiles)
            .context("failed to canonicalize baseline disclosure_profiles")?,
    )?;
    if review.get("disclosure_digest").and_then(Value::as_str)
        != Some(computed_disclosure_digest.as_str())
    {
        bail!("baseline review disclosure digest does not match its profiles");
    }

    let required = validate_required_review_classes(
        review
            .get("required_reviews")
            .ok_or_else(|| anyhow!("baseline review record lacks required_reviews"))?,
    )?;
    let review_digests = review
        .get("review_digests")
        .ok_or_else(|| anyhow!("baseline review record lacks review_digests"))?;
    validate_review_digest_slots(
        review_digests,
        Some(&required),
        "baseline review_digests",
    )?;
    let review_digests = review_digests
        .as_object()
        .ok_or_else(|| anyhow!("baseline review_digests must be an object"))?;
    let claim_review_digest = digest_json(&json!({
        "semantic": semantic["claim"],
        "disclosure": computed_disclosure_digest,
    }))?;
    let country_policy_review_digest = digest_json(&json!({
        "semantic": semantic["country_policy"],
        "disclosure": computed_disclosure_digest,
    }))?;
    let integration_digest = semantic
        .get("integration")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("baseline integration semantic digest is invalid"))?;
    let operator_security_digest = semantic
        .get("operator_security")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("baseline operator-security semantic digest is invalid"))?;
    for (class, expected) in [
        ("claim", claim_review_digest.as_str()),
        ("integration", integration_digest),
        ("country_policy", country_policy_review_digest.as_str()),
        ("operator_security", operator_security_digest),
    ] {
        if required.contains(class)
            && review_digests.get(class).and_then(Value::as_str) != Some(expected)
        {
            bail!("baseline review digest does not match its signed review inputs");
        }
    }
    validate_semantic_changes(
        review
            .get("semantic_changes")
            .ok_or_else(|| anyhow!("baseline review record lacks semantic_changes"))?,
    )?;
    validate_nested_baseline(review.get("baseline"))?;
    if !review
        .get("entity_materializations")
        .is_some_and(Value::is_object)
    {
        bail!("baseline review entity_materializations must be an object");
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

fn validate_required_review_classes(value: &Value) -> Result<BTreeSet<String>> {
    let reviews = value
        .as_array()
        .ok_or_else(|| anyhow!("baseline required_reviews must be an array"))?;
    let mut required = BTreeSet::new();
    for review in reviews {
        let review = review
            .as_str()
            .ok_or_else(|| anyhow!("baseline required review must be a string"))?;
        if !matches!(
            review,
            "claim" | "integration" | "country_policy" | "operator_security"
        ) || !required.insert(review.to_string())
        {
            bail!("baseline required_reviews contain an unknown or duplicate class");
        }
    }
    Ok(required)
}

fn validate_review_digest_slots(
    value: &Value,
    required: Option<&BTreeSet<String>>,
    label: &str,
) -> Result<()> {
    let slots = exact_review_object(
        value,
        &["claim", "integration", "country_policy", "operator_security"],
        label,
    )?;
    for class in ["claim", "integration", "country_policy", "operator_security"] {
        let value = slots
            .get(class)
            .ok_or_else(|| anyhow!("{label} lacks {class}"))?;
        validate_review_sha256(Some(value), class, true)?;
        if let Some(required) = required {
            if required.contains(class) == value.is_null() {
                bail!("baseline review digest slots do not match required_reviews");
            }
        }
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
            &["dimension", "previous_digest", "current_digest"],
            "baseline semantic change",
        )?;
        let dimension = change
            .get("dimension")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("baseline semantic change dimension must be a string"))?;
        if !matches!(
            dimension,
            "claim" | "integration" | "country_policy" | "operator_security" | "disclosure"
        ) || !dimensions.insert(dimension)
        {
            bail!("baseline semantic_changes contain an unknown or duplicate dimension");
        }
        validate_review_sha256(change.get("previous_digest"), "previous_digest", true)?;
        validate_review_sha256(change.get("current_digest"), "current_digest", false)?;
    }
    Ok(())
}

fn validate_nested_baseline(value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        bail!("baseline review record lacks baseline");
    };
    if value.is_null() {
        return Ok(());
    }
    let baseline = exact_review_object(
        value,
        &[
            "review_digest",
            "review_digests",
            "authored_input_digest",
            "verified_manifest",
        ],
        "baseline review baseline",
    )?;
    validate_review_sha256(baseline.get("review_digest"), "review_digest", false)?;
    validate_review_digest_slots(
        baseline
            .get("review_digests")
            .ok_or_else(|| anyhow!("baseline review baseline lacks review_digests"))?,
        None,
        "baseline prior review_digests",
    )?;
    validate_review_sha256(
        baseline.get("authored_input_digest"),
        "authored_input_digest",
        true,
    )?;
    let manifest: registry_platform_config::ConfigBundleManifest = serde_json::from_value(
        baseline
            .get("verified_manifest")
            .cloned()
            .ok_or_else(|| anyhow!("baseline review baseline lacks verified_manifest"))?,
    )
    .context("baseline prior verified_manifest is invalid")?;
    manifest
        .validate()
        .context("baseline prior verified_manifest is invalid")?;
    Ok(())
}

fn required_reviews(
    loaded: &LoadedCountryProject,
    baseline: Option<&Value>,
) -> BTreeSet<ReviewClass> {
    let Some(baseline) = baseline else {
        return BTreeSet::from([
            ReviewClass::Claim,
            ReviewClass::Integration,
            ReviewClass::CountryPolicy,
            ReviewClass::OperatorSecurity,
        ]);
    };
    let mut reviews = BTreeSet::new();
    for (class, field, current) in [
        (
            ReviewClass::Claim,
            "claim",
            loaded.semantic_digests.claim.as_str(),
        ),
        (
            ReviewClass::Integration,
            "integration",
            loaded.semantic_digests.integration.as_str(),
        ),
        (
            ReviewClass::CountryPolicy,
            "country_policy",
            loaded.semantic_digests.country_policy.as_str(),
        ),
        (
            ReviewClass::OperatorSecurity,
            "operator_security",
            loaded.semantic_digests.operator_security.as_str(),
        ),
    ] {
        if baseline
            .get("semantic_digests")
            .and_then(|digests| digests.get(field))
            .and_then(Value::as_str)
            != Some(current)
        {
            reviews.insert(class);
        }
    }
    let disclosure_profiles = disclosure_review_profiles(&loaded.project);
    let (disclosure_narrowed, disclosure_widened) =
        disclosure_change_classes(&disclosure_profiles, Some(baseline));
    if disclosure_narrowed {
        reviews.insert(ReviewClass::Claim);
    }
    if disclosure_widened {
        reviews.insert(ReviewClass::CountryPolicy);
    }
    reviews
}

fn null_review_digests() -> Value {
    json!({
        "claim": null,
        "integration": null,
        "country_policy": null,
        "operator_security": null,
    })
}

fn semantic_change_records(
    loaded: &LoadedCountryProject,
    baseline: Option<&Value>,
    disclosure_digest: &str,
) -> Vec<SemanticChange> {
    [
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
            "country_policy",
            loaded.semantic_digests.country_policy.as_str(),
            baseline
                .and_then(|review| review.get("semantic_digests"))
                .and_then(|digests| digests.get("country_policy"))
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
    .map(|(dimension, current, previous)| SemanticChange {
        dimension,
        previous_digest: previous.map(str::to_string),
        current_digest: current.to_string(),
    })
    .collect()
}

fn canonical_root(root: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to stat country project {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("country project root must be a real directory");
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
        bail!("authored file escapes the country project root");
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
        bail!("authored reference escapes the country project root");
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
        .map_err(|_| anyhow!("path is outside country project root"))?;
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
        bail!("symlinks are forbidden at the country authoring boundary");
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
        if metadata.file_type().is_symlink() || metadata.is_dir() {
            bail!("fixture directories may contain only direct regular YAML files");
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
    paths
        .into_iter()
        .map(|path| {
            let bytes = read_authored_file(root, &path)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| anyhow!("fixture escapes country project root"))?;
            hash_authored_file(
                hasher,
                relative
                    .to_str()
                    .ok_or_else(|| anyhow!("fixture path is not Unicode"))?,
                &bytes,
            );
            let fixture = parse_yaml(&bytes, &relative.display().to_string())?;
            Ok((path, fixture))
        })
        .collect()
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_yaml::from_slice(bytes).with_context(|| format!("invalid authored YAML in {label}"))
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

fn validate_environment_credential(
    interface: &CredentialInterface,
    binding: &EnvironmentIntegration,
) -> Result<()> {
    match (&interface.credential_type, &binding.credential) {
        (CredentialType::None, None) => Ok(()),
        (expected, Some(credential))
            if std::mem::discriminant(expected)
                == std::mem::discriminant(&credential.credential_type)
                && credential.generation > 0 =>
        {
            for reference in [
                credential.username.as_ref(),
                credential.password.as_ref(),
                credential.token.as_ref(),
                credential.client_id.as_ref(),
                credential.client_secret.as_ref(),
                credential.value.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_secret_reference(reference)?;
            }
            let exact = match credential.credential_type {
                CredentialType::None => false,
                CredentialType::Basic => {
                    credential.username.is_some()
                        && credential.password.is_some()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::StaticBearer => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_some()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::Oauth2ClientCredentials => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_some()
                        && credential.client_secret.is_some()
                        && credential.value.is_none()
                        && credential.review.is_none()
                        && binding.credential_destination.is_some()
                }
                CredentialType::ApiKeyHeader => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_some()
                        && credential.review.is_none()
                        && binding.credential_destination.is_none()
                }
                CredentialType::ApiKeyQuery => {
                    credential.username.is_none()
                        && credential.password.is_none()
                        && credential.token.is_none()
                        && credential.client_id.is_none()
                        && credential.client_secret.is_none()
                        && credential.value.is_some()
                        && credential.review == Some(ReviewClassInput::OperatorSecurity)
                        && binding.credential_destination.is_none()
                }
            };
            if !exact {
                bail!("environment credential fields do not match the closed credential type");
            }
            if let Some(destination) = &binding.credential_destination {
                validate_https_origin(&destination.origin, "credential destination")?;
            }
            Ok(())
        }
        _ => bail!("environment credential does not match the reviewed integration interface"),
    }
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

fn validate_absolute_runtime_path(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().as_encoded_bytes().len() > 4096 || !path.is_absolute() {
        bail!("{field} must be one bounded absolute path");
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                bail!("{field} must be normalized and cannot traverse")
            }
        }
    }
    Ok(())
}

fn parse_duration_ms(value: &str) -> Result<u32> {
    parse_duration_ms_with_max(value, 20_000, "deadline")
}

fn parse_duration_ms_with_max(value: &str, maximum: u32, label: &str) -> Result<u32> {
    let milliseconds = if let Some(seconds) = value.strip_suffix('s') {
        seconds.parse::<u32>()?.checked_mul(1000)
    } else if let Some(milliseconds) = value.strip_suffix("ms") {
        Some(milliseconds.parse::<u32>()?)
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
