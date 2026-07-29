// SPDX-License-Identifier: Apache-2.0

fn load_registry_project(root: &Path, environment: Option<&str>) -> Result<LoadedRegistryProject> {
    let root = canonical_root(root)?;
    let project_path = root.join(PROJECT_FILE);
    let project_bytes = read_authored_file(&root, &project_path)?;
    let project: RegistryProject = parse_yaml(&project_bytes, PROJECT_FILE)?;
    validate_project_shape(&project)?;

    let mut hasher = Sha256::new();
    let mut artifact_inputs = BTreeMap::new();
    record_artifact_input(&mut artifact_inputs, PROJECT_FILE, &project_bytes)?;
    hash_authored_file(
        &mut hasher,
        PROJECT_FILE,
        &project_digest_document(&project)?,
    );
    let mut entities = BTreeMap::new();
    for (alias, reference) in &project.entities {
        let relative = &reference.file;
        let path = resolve_authored_path(&root, relative)?;
        let bytes = read_authored_file(&root, &path)?;
        let relative = relative
            .to_str()
            .ok_or_else(|| anyhow!("entity definition path is not Unicode"))?;
        record_artifact_input(&mut artifact_inputs, relative, &bytes)?;
        hash_authored_file(&mut hasher, relative, &bytes);
        let document: EntityDefinition = parse_yaml(&bytes, relative)?;
        validate_entity_definition(&document)?;
        if alias != &document.id {
            bail!("entity alias must match the referenced entity id");
        }
        if entities
            .insert(document.id.clone(), LoadedEntityDefinition { document })
            .is_some()
        {
            bail!("one entity cannot be declared more than once");
        }
    }
    let mut integrations = BTreeMap::new();
    for (alias, reference) in &project.integrations {
        let path = resolve_authored_path(&root, &reference.file)?;
        let bytes = read_authored_file(&root, &path)?;
        let integration_relative = reference
            .file
            .to_str()
            .ok_or_else(|| anyhow!("integration path is not Unicode"))?;
        record_artifact_input(&mut artifact_inputs, integration_relative, &bytes)?;
        hash_authored_file(&mut hasher, integration_relative, &bytes);
        let authored: AuthoredIntegrationDocument =
            parse_yaml(&bytes, &reference.file.display().to_string())?;
        let document = lower_project_integration(&authored, &entities)?;
        validate_integration(alias, &document).with_context(|| {
            format!("invalid authored integration {}", reference.file.display())
        })?;
        let fixture_dir = path
            .parent()
            .ok_or_else(|| anyhow!("integration file has no parent"))?
            .join(&document.fixtures);
        let fixtures = load_fixtures(&root, &fixture_dir, &mut hasher, &mut artifact_inputs)?;
        validate_fixture_inputs(alias, &document, &fixtures)?;
        let script = integration_script(&document)
            .map(|script| {
                let script_path = resolve_relative_to_file(&root, &path, script)?;
                let script_bytes = read_authored_file(&root, &script_path)?;
                let relative = script_path
                    .strip_prefix(&root)
                    .map_err(|_| anyhow!("script path escapes project root"))?;
                let relative = relative
                    .to_str()
                    .ok_or_else(|| anyhow!("script path is not Unicode"))?;
                record_artifact_input(&mut artifact_inputs, relative, &script_bytes)?;
                hash_authored_file(&mut hasher, relative, &script_bytes);
                Ok::<(PathBuf, Box<[u8]>), anyhow::Error>((
                    script_path,
                    script_bytes.into_boxed_slice(),
                ))
            })
            .transpose()?;
        let mut script_modules = Vec::new();
        if let CapabilityDeclaration::Script { script } = &document.capability {
            let mut resolved_modules = BTreeSet::new();
            for module in &script.modules {
                if module.extension().and_then(std::ffi::OsStr::to_str) != Some("rhai") {
                    bail!("script modules must use the .rhai extension");
                }
                let module_path = resolve_relative_to_file(&root, &path, module)?;
                if !resolved_modules.insert(module_path.clone()) {
                    bail!("script modules must resolve to unique authored files");
                }
                let module_bytes = read_authored_file(&root, &module_path)?;
                let relative = module_path
                    .strip_prefix(&root)
                    .map_err(|_| anyhow!("script module path escapes project root"))?;
                let relative = relative
                    .to_str()
                    .ok_or_else(|| anyhow!("script module path is not Unicode"))?;
                record_artifact_input(&mut artifact_inputs, relative, &module_bytes)?;
                hash_authored_file(&mut hasher, relative, &module_bytes);
                script_modules.push((module_path, module_bytes.into_boxed_slice()));
            }
        }
        validate_not_applicable(
            alias,
            &document,
            &fixtures,
            &entities,
            script.as_ref(),
            &script_modules,
        )?;
        integrations.insert(
            alias.clone(),
            LoadedIntegration {
                document,
                fixtures,
                script,
                script_modules,
            },
        );
    }
    validate_service_integration_links(&project, &integrations)?;
    validate_project_entity_links(&project, &integrations, &entities)?;

    let project_content_digest = project_content_digest(&root, &hasher)?;

    let (environment_name, environment) = match environment {
        Some(name) => {
            validate_stable_id(name, "environment")?;
            let relative = PathBuf::from("environments").join(format!("{name}.yaml"));
            let path = resolve_authored_path(&root, &relative)?;
            let bytes = read_authored_file(&root, &path)?;
            let environment_relative = relative
                .to_str()
                .ok_or_else(|| anyhow!("environment path is not Unicode"))?;
            record_artifact_input(&mut artifact_inputs, environment_relative, &bytes)?;
            hash_authored_file(&mut hasher, environment_relative, &bytes);
            let document: EnvironmentDocument =
                parse_yaml(&bytes, &relative.display().to_string())?;
            validate_environment(&project, &integrations, &entities, &document)?;
            validate_environment_project_files(&root, &document)?;
            (Some(name.to_owned()), Some(document))
        }
        None => (None, None),
    };
    let semantic_digests =
        semantic_digests(&project, &integrations, &entities, environment.as_ref())?;
    Ok(LoadedRegistryProject {
        root,
        project,
        environment_name,
        environment,
        integrations,
        entities,
        authored_hash: format!("sha256:{}", hex::encode(hasher.finalize())),
        artifact_inputs: artifact_inputs.into_values().collect(),
        project_content_digest,
        semantic_digests,
    })
}

fn record_artifact_input(
    artifact_inputs: &mut BTreeMap<String, ArtifactInputDigest>,
    relative: &str,
    bytes: &[u8],
) -> Result<()> {
    let path = ProjectRelativePath::new(relative.to_owned())
        .map_err(|error| anyhow!("authored input path is invalid: {error}"))?;
    let digest = Sha256Digest::new(sha256_uri(bytes))
        .map_err(|error| anyhow!("authored input digest is invalid: {error}"))?;
    if artifact_inputs
        .insert(
            relative.to_owned(),
            ArtifactInputDigest {
                path,
                digest,
                classification: ArtifactInputClassification::AuthoredProjectInput,
            },
        )
        .is_some()
    {
        bail!("one authored input cannot be loaded more than once");
    }
    Ok(())
}

fn project_content_digest(root: &Path, authored_hasher: &Sha256) -> Result<String> {
    let directory = root.join("environments");
    if !directory.exists() {
        return Ok(format!(
            "sha256:{}",
            hex::encode(authored_hasher.clone().finalize())
        ));
    }
    reject_symlink_components(root, &directory)?;
    if !fs::symlink_metadata(&directory)
        .context("failed to inspect project environments")?
        .is_dir()
    {
        bail!("project environments path must be a real directory");
    }
    let mut paths = fs::read_dir(&directory)
        .context("failed to read project environments")?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|path| path.extension().and_then(OsStr::to_str) == Some("yaml"));
    paths.sort();
    if paths.len() > MAX_ENVIRONMENTS {
        bail!("project must declare no more than {MAX_ENVIRONMENTS} environments");
    }

    let mut hasher = authored_hasher.clone();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| anyhow!("environment path escapes project root"))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| anyhow!("environment path is not Unicode"))?;
        let bytes = read_authored_file(root, &path)?;
        hash_authored_file(&mut hasher, relative, &bytes);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn project_digest_document(project: &RegistryProject) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(project)
        .context("failed to serialize project for starter provenance")?;
    if let Some(starter) = value.get_mut("starter").and_then(Value::as_object_mut) {
        starter.remove("content_digest");
    }
    canonicalize_json(&value).context("failed to canonicalize project for starter provenance")
}

fn lower_project_integration(
    authored: &AuthoredIntegrationDocument,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
) -> Result<IntegrationDocument> {
    let AuthoredCapabilityDeclaration::Snapshot(AuthoredSnapshotCapability { snapshot }) =
        &authored.capability
    else {
        return lower_authored_integration(authored);
    };
    validate_authored_integration_contract(authored)?;
    let AuthoredOutputsDeclaration::EntityFields(output_names) = &authored.outputs else {
        bail!("snapshot outputs must be a non-empty list of entity fields");
    };
    if output_names.is_empty() || output_names.len() > MAX_OUTPUTS {
        bail!("snapshot outputs must contain between one and {MAX_OUTPUTS} entity fields");
    }
    let entity = &entities
        .get(&snapshot.entity)
        .ok_or_else(|| anyhow!("snapshot references unknown entity {}", snapshot.entity))?
        .document;
    let mut unique_outputs = BTreeSet::new();
    let outputs = output_names
        .iter()
        .map(|name| {
            validate_input_name(name).with_context(|| format!("snapshot output {name}"))?;
            if !unique_outputs.insert(name) {
                bail!("snapshot outputs must be unique");
            }
            let field = entity
                .schema
                .properties
                .get(name)
                .ok_or_else(|| anyhow!("snapshot output {name} is not an entity property"))?;
            let (output_type, nullable, max_bytes) = entity_output_contract(name, field)?;
            if max_bytes.is_some_and(|bytes| bytes > 64 * 1024) {
                bail!("snapshot output {name} exceeds the 64KiB scalar release ceiling");
            }
            Ok((
                name.clone(),
                OutputDeclaration {
                    output_type,
                    nullable,
                    max_bytes,
                    minimum: field.minimum,
                    maximum: field.maximum,
                    structured_schema: None,
                    from: Some(format!("snapshot.record.{name}")),
                    source_pointer: None,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if snapshot.exact.is_empty() || snapshot.exact.len() > 8 {
        bail!("snapshot exact must contain between one and eight entity selectors");
    }
    let exact = snapshot
        .exact
        .iter()
        .map(|(field, reference)| {
            let entity_field =
                entity.schema.properties.get(field).ok_or_else(|| {
                    anyhow!("snapshot exact field {field} is not an entity property")
                })?;
            if entity_field_nullable(entity_field)? {
                bail!("snapshot exact fields cannot be nullable");
            }
            let input = authored.input.get(&reference.input).ok_or_else(|| {
                anyhow!(
                    "snapshot exact references unknown input {}",
                    reference.input
                )
            })?;
            if input.role != AuthoredInputRole::Selector {
                bail!("snapshot exact may reference only selector inputs");
            }
            Ok((field.clone(), reference.input.clone()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    if exact.values().collect::<BTreeSet<_>>() != authored.input.keys().collect::<BTreeSet<_>>() {
        bail!("snapshot exact must bind every integration input exactly once");
    }
    parse_snapshot_freshness_ms(&snapshot.freshness)?;
    let input = authored
        .input
        .iter()
        .map(|(name, declaration)| {
            let schema = lower_input_schema(name, declaration)?;
            Ok((
                name.clone(),
                InputDeclaration {
                    role: declaration.role,
                    input_type: schema.input_type,
                    nullable: schema.nullable,
                    max_length: schema.max_length,
                    min_length: schema.min_length,
                    bytes: schema.max_bytes,
                    pattern: schema.pattern,
                    enum_values: schema.enum_values,
                    const_value: schema.const_value,
                    canonicalization: declaration
                        .canonicalization
                        .clone()
                        .unwrap_or(Canonicalization::Identity),
                    minimum: schema.minimum,
                    maximum: schema.maximum,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(IntegrationDocument {
        version: authored.version,
        id: authored.id.clone(),
        revision: authored.revision,
        source: SourceDeclaration {
            product: None,
            versions: SourceVersions::default(),
        },
        input,
        capability: CapabilityDeclaration::Snapshot {
            snapshot: SnapshotDeclaration {
                entity: snapshot.entity.clone(),
                exact,
                cardinality: CardinalityMode::ProbeTwo,
                freshness: snapshot.freshness.clone(),
                materialization: SnapshotFootprint {
                    max_source_records: entity.materialization.max_records,
                    max_source_bytes: parse_entity_generation_bytes(
                        &entity.materialization.max_bytes,
                    )?,
                },
            },
        },
        outputs,
        not_applicable: NotApplicableDeclaration {
            ambiguity: authored.not_applicable.ambiguity.as_ref().map(|reason| {
                NotApplicableReason {
                    rationale: reason.rationale.clone(),
                    request_fixture: reason.request_fixture.clone(),
                }
            }),
            subject_mismatch: authored
                .not_applicable
                .subject_mismatch
                .as_ref()
                .map(|reason| NotApplicableReason {
                    rationale: reason.rationale.clone(),
                    request_fixture: reason.request_fixture.clone(),
                }),
        },
        bounds: BoundsDeclaration {
            calls: 0,
            calls_authored: false,
            source_bytes: 1024 * 1024,
            source_bytes_authored: false,
            request_bytes: 64 * 1024,
            request_bytes_authored: false,
            deadline: "15s".to_string(),
            deadline_authored: false,
            concurrency: 8,
        },
        fixtures: PathBuf::from("fixtures"),
    })
}

fn validate_not_applicable(
    alias: &str,
    integration: &IntegrationDocument,
    fixtures: &[(PathBuf, FixtureDocument)],
    entities: &BTreeMap<String, LoadedEntityDefinition>,
    script: Option<&(PathBuf, Box<[u8]>)>,
    script_modules: &[(PathBuf, Box<[u8]>)],
) -> Result<()> {
    let ambiguous_fixtures = fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.outcome.as_deref() == Some("ambiguous"))
        .map(|(_, fixture)| fixture.name.as_str())
        .collect::<Vec<_>>();
    if let Some(reason) = &integration.not_applicable.ambiguity {
        if !ambiguous_fixtures.is_empty() {
            bail!(
                "integration {alias} declares ambiguity not applicable but also provides ambiguous fixtures: {}",
                ambiguous_fixtures.join(", ")
            );
        }
        let _ = validate_not_applicable_evidence(alias, "ambiguity", reason, fixtures)?;
        if let CapabilityDeclaration::Snapshot { snapshot } = &integration.capability {
            let entity = entities.get(&snapshot.entity).ok_or_else(|| {
                anyhow!("snapshot ambiguity evidence references an unknown entity")
            })?;
            if !snapshot.exact.contains_key(&entity.document.primary_key) {
                bail!(
                    "snapshot ambiguity may be not_applicable only when exact selectors include the entity primary_key"
                );
            }
        }
    } else {
        if ambiguous_fixtures.is_empty() {
            bail!(
                "integration {alias} must provide an ambiguous fixture or declare not_applicable.ambiguity with request evidence"
            );
        }
    }

    validate_subject_mismatch_contract(alias, integration, fixtures, script, script_modules)?;
    Ok(())
}

fn validate_not_applicable_evidence<'a>(
    alias: &str,
    field: &str,
    reason: &NotApplicableReason,
    fixtures: &'a [(PathBuf, FixtureDocument)],
) -> Result<&'a FixtureDocument> {
    let evidence = fixtures
        .iter()
        .find(|(_, fixture)| fixture.name == reason.request_fixture)
        .map(|(_, fixture)| fixture)
        .ok_or_else(|| {
            anyhow!(
                "integration {alias} not_applicable.{field}.request_fixture references missing fixture {}",
                reason.request_fixture
            )
        })?;
    if evidence.interactions.is_empty()
        || evidence.expect.error.is_some()
        || !matches!(
            evidence.expect.outcome.as_deref(),
            None | Some("match" | "no_match")
        )
    {
        bail!(
            "integration {alias} {field} request evidence must contain a source request and expect match or no_match"
        );
    }
    Ok(evidence)
}

fn validate_subject_mismatch_contract(
    alias: &str,
    integration: &IntegrationDocument,
    fixtures: &[(PathBuf, FixtureDocument)],
    script: Option<&(PathBuf, Box<[u8]>)>,
    script_modules: &[(PathBuf, Box<[u8]>)],
) -> Result<()> {
    const SUBJECT_MISMATCH: &str = "failure.subject_mismatch";
    let mismatch_fixtures = fixtures
        .iter()
        .filter(|(_, fixture)| fixture.expect.error.as_deref() == Some(SUBJECT_MISMATCH))
        .map(|(_, fixture)| fixture.name.as_str())
        .collect::<Vec<_>>();
    let script_checks_mismatch = script
        .into_iter()
        .map(|(_, bytes)| bytes.as_ref())
        .chain(script_modules.iter().map(|(_, bytes)| bytes.as_ref()))
        .any(|bytes| {
            bytes
                .windows(SUBJECT_MISMATCH.len())
                .any(|window| window == SUBJECT_MISMATCH.as_bytes())
        });
    let protocol_checks_mismatch = matches!(
        &integration.capability,
        CapabilityDeclaration::Script { script } if script.signed_dci.is_some()
    );

    if script_checks_mismatch {
        if integration.not_applicable.subject_mismatch.is_some() {
            bail!(
                "integration {alias} declares subject mismatch not applicable but its reviewed script checks failure.subject_mismatch"
            );
        }
        if mismatch_fixtures.is_empty() {
            bail!(
                "integration {alias} must provide a fixture expecting failure.subject_mismatch because its reviewed script compares an echoed subject identifier"
            );
        }
        return Ok(());
    }
    if protocol_checks_mismatch {
        if integration.not_applicable.subject_mismatch.is_some() {
            bail!(
                "integration {alias} cannot declare subject mismatch not applicable because signed DCI binds selectors to comparable response identifiers"
            );
        }
        return Ok(());
    }
    if !mismatch_fixtures.is_empty() {
        bail!(
            "integration {alias} provides subject mismatch fixtures but its reviewed capability has no failure.subject_mismatch comparison"
        );
    }

    let reason = integration
        .not_applicable
        .subject_mismatch
        .as_ref()
        .ok_or_else(|| {
            anyhow!(
                "integration {alias} must provide a fixture expecting failure.subject_mismatch or declare not_applicable.subject_mismatch with request evidence"
            )
        })?;
    let evidence = validate_not_applicable_evidence(alias, "subject_mismatch", reason, fixtures)?;
    if exposes_comparable_subject(integration) {
        bail!(
            "integration {alias} subject mismatch may be not_applicable only when the reviewed response contract has no selector-comparable identifier"
        );
    }
    let selector_values = integration
        .input
        .iter()
        .filter(|(_, declaration)| declaration.role == AuthoredInputRole::Selector)
        .filter_map(|(name, _)| evidence.input.get(name))
        .collect::<Vec<_>>();
    if evidence
        .interactions
        .iter()
        .any(|interaction| match &interaction.respond {
            FixtureSourceResponse::Http { body, .. } => selector_values
                .iter()
                .any(|selector| json_contains_scalar(body, selector)),
            FixtureSourceResponse::Timeout { .. } => false,
        })
    {
        bail!(
            "integration {alias} subject mismatch request evidence contains a selector-comparable response identifier"
        );
    }
    Ok(())
}

fn exposes_comparable_subject(integration: &IntegrationDocument) -> bool {
    let selectors = integration
        .input
        .iter()
        .filter(|(_, declaration)| declaration.role == AuthoredInputRole::Selector)
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    let snapshot_subject_fields = match &integration.capability {
        CapabilityDeclaration::Snapshot { snapshot } => snapshot
            .exact
            .iter()
            .filter(|(_, input)| selectors.contains(input.as_str()))
            .map(|(field, _)| field.as_str())
            .collect::<BTreeSet<_>>(),
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
            BTreeSet::new()
        }
    };
    integration.outputs.iter().any(|(name, output)| {
        selectors.contains(name.as_str())
            || snapshot_subject_fields.contains(name.as_str())
            || output.from.as_deref().is_some_and(|from| {
                from.rsplit('.')
                    .next()
                    .is_some_and(|field| snapshot_subject_fields.contains(field))
            })
            || output.source_pointer.as_deref().is_some_and(|pointer| {
                pointer
                    .rsplit('/')
                    .next()
                    .is_some_and(|segment| selectors.contains(segment))
            })
    })
}

fn json_contains_scalar(value: &Value, expected: &Value) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_scalar(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| json_contains_scalar(value, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value == expected,
    }
}

fn entity_output_contract(
    name: &str,
    field: &EntityFieldSchema,
) -> Result<(OutputType, bool, Option<u32>)> {
    let (scalar, nullable) = schema_type_parts(&field.field_type)?;
    let (output_type, max_bytes) = match (scalar, field.format) {
        (AuthoredScalarType::String, Some(AuthoredStringFormat::Date)) => {
            if field.max_length != Some(10) {
                bail!("entity field {name} date format requires maxLength: 10");
            }
            (OutputType::Date, None)
        }
        (AuthoredScalarType::String, None) => {
            let max_length = field
                .max_length
                .ok_or_else(|| anyhow!("entity String field {name} requires maxLength"))?;
            if field.min_length.is_some_and(|minimum| minimum > max_length)
                || field
                    .pattern
                    .as_ref()
                    .is_some_and(|pattern| pattern.is_empty() || pattern.len() > 16_384)
                || field.minimum.is_some()
                || field.maximum.is_some()
            {
                bail!("entity String field {name} has incompatible constraints");
            }
            (
                OutputType::String,
                Some(
                    max_length
                        .checked_mul(4)
                        .ok_or_else(|| anyhow!("entity field {name} UTF-8 byte bound overflows"))?,
                ),
            )
        }
        (AuthoredScalarType::Boolean, None) => {
            if field.max_length.is_some()
                || field.min_length.is_some()
                || field.pattern.is_some()
                || field.minimum.is_some()
                || field.maximum.is_some()
            {
                bail!("entity Boolean field {name} has incompatible constraints");
            }
            (OutputType::Boolean, None)
        }
        (AuthoredScalarType::Integer, None) => {
            let minimum = field
                .minimum
                .ok_or_else(|| anyhow!("entity Integer field {name} requires minimum"))?;
            let maximum = field
                .maximum
                .ok_or_else(|| anyhow!("entity Integer field {name} requires maximum"))?;
            const JSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
            if minimum > maximum
                || minimum < -JSON_SAFE_INTEGER
                || maximum > JSON_SAFE_INTEGER
                || field.max_length.is_some()
                || field.min_length.is_some()
                || field.pattern.is_some()
            {
                bail!("entity Integer field {name} has incompatible constraints");
            }
            (OutputType::Integer, None)
        }
        (AuthoredScalarType::Null, _) => bail!("entity field {name} cannot have only null type"),
        (_, Some(_)) => bail!("entity field {name} format is valid only for String"),
    };
    for value in field
        .enum_values
        .iter()
        .flatten()
        .chain(field.const_value.iter())
    {
        let matches = value.is_null() && nullable
            || matches!(
                scalar,
                AuthoredScalarType::String if value.is_string()
            )
            || matches!(scalar, AuthoredScalarType::Boolean if value.is_boolean())
            || matches!(scalar, AuthoredScalarType::Integer if value.as_i64().is_some());
        if !matches {
            bail!("entity field {name} enum/const value violates its scalar type");
        }
    }
    Ok((output_type, nullable, max_bytes))
}

fn entity_field_nullable(field: &EntityFieldSchema) -> Result<bool> {
    Ok(schema_type_parts(&field.field_type)?.1)
}

fn semantic_digests(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
    environment: Option<&EnvironmentDocument>,
) -> Result<SemanticDigests> {
    let claims = project
        .services
        .iter()
        .map(|(id, service)| {
            let service_claims = service
                .claims
                .iter()
                .map(|(claim_id, claim)| {
                    Ok((
                        claim_id,
                        json!({
                            "evidence": inferred_claim_evidence(service, claim)?,
                            "output": claim.output,
                            "cel": claim.cel,
                            "value": claim.value,
                        }),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            Ok((
                id,
                json!({
                    "subject_type": service.effective_subject_type(),
                    "variables": service.variables,
                    "claims": service_claims,
                }),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let policy = project
        .services
        .iter()
        .map(|(id, service)| {
            (
                id,
                json!({
                    "purpose": service.purpose,
                    "legal_basis": service.legal_basis,
                    "consent": service.consent,
                    "access": service.access,
                    "credential_profiles": service.credential_profiles,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_policy = project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::RecordsApi)
        .map(|(id, service)| {
            (
                id,
                json!({
                    "entity": service.entity,
                    "title": service.title,
                    "description": service.description,
                    "owner": service.owner,
                    "sensitivity": service.sensitivity,
                    "access_rights": service.access_rights,
                    "update_frequency": service.update_frequency,
                    "conforms_to": service.conforms_to,
                    "api": service.api,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let entity_model = entities
        .iter()
        .map(|(id, loaded)| {
            let definition = &loaded.document;
            (
                id,
                json!({
                    "version": definition.version,
                    "id": definition.id,
                    "revision": definition.revision,
                    "primary_key": definition.primary_key,
                    "schema": definition.schema,
                    "materialization": definition.materialization,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let integration = integrations
        .iter()
        .map(|(alias, loaded)| {
            let fixture_digests = loaded
                .fixtures
                .iter()
                .map(|(path, fixture)| {
                    let name = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| anyhow!("fixture path is not Unicode"))?;
                    Ok((name, fixture))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            let script_digest = loaded.script.as_ref().map(|(_, script)| sha256_uri(script));
            let snapshot_mapping = match &loaded.document.capability {
                CapabilityDeclaration::Snapshot { snapshot } => environment
                    .and_then(|environment| environment.entities.get(&snapshot.entity))
                    .map(|binding| json!({ "columns": binding.columns })),
                CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => None,
            };
            Ok((
                alias,
                json!({
                    "document": loaded.document,
                    "fixtures": fixture_digests,
                    "script_digest": script_digest,
                    "snapshot_mapping": snapshot_mapping,
                }),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let service_consultations = project
        .services
        .iter()
        .map(|(service, declaration)| (service, &declaration.consultations))
        .collect::<BTreeMap<_, _>>();
    let callers = environment.map(|environment| {
        environment
            .callers
            .iter()
            .map(|(id, caller)| (id, &caller.scopes))
            .collect::<BTreeMap<_, _>>()
    });
    let operator = environment.map(|environment| {
        let integrations = environment
            .integrations
            .iter()
            .map(|(alias, binding)| {
                (
                    alias,
                    json!({
                        "source": binding.source,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let caller_credentials = environment
            .callers
            .iter()
            .map(|(id, caller)| (id, &caller.api_key_fingerprint))
            .collect::<BTreeMap<_, _>>();
        let mut operator = json!({
            "integrations": integrations,
            "entities": environment.entities,
            "caller_credentials": caller_credentials,
            "issuance": environment.issuance,
            "relay": environment.relay,
            "notary_relay": environment.notary_relay,
            "notary_state": environment.notary_state,
            "oid4vci_registrar_clients": environment.oid4vci.as_ref()
                .map(|binding| &binding.registrar_clients),
            "deployment": environment.deployment,
        });
        if let Some(relay_state) = &environment.relay_state {
            operator["relay_state"] = json!(relay_state);
        }
        if let Some(notary_cel) = &environment.notary_cel {
            operator["notary_cel"] = json!(notary_cel);
        }
        operator
    });
    Ok(SemanticDigests {
        claim: digest_json(&json!({ "services": claims }))?,
        integration: digest_json(&json!({
            "integrations": integration,
            "service_consultations": service_consultations,
            "entities": entity_model,
        }))?,
        service_policy: digest_json(
            &json!({ "services": policy, "records": records_policy, "callers": callers }),
        )?,
        operator_security: digest_json(&json!({ "operator": operator }))?,
    })
}

// This reviewed revision binds every currently published field-knowledge path,
// its ownership/classification metadata, and its explicit promotion mapping.
// A schema or knowledge change must therefore be reviewed for promotion
// semantics before a new projection can be emitted.
const PROMOTION_FIELD_KNOWLEDGE_REVISION: &str =
    "sha256:5f2fa5cff59147791a8d8af3d4ee5fc3c8cfdd053877e681a0d1b9a06b1601bf";

fn project_promotion_projection(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Result<ProjectPromotionProjectionV1> {
    let field_knowledge_revision = validate_promotion_field_knowledge_mapping()?;

    let products = project_promotion_products(environment);
    let capabilities = project_promotion_capabilities(loaded, environment);
    let origins = environment
        .integrations
        .iter()
        .map(|(alias, binding)| {
            (
                alias,
                json!({
                    "source": binding.source.origin,
                    "oauth": binding.source.oauth.as_ref().map(|endpoint| &endpoint.origin),
                    "jwks": binding.source.jwks.as_ref().map(|endpoint| &endpoint.origin),
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let origin_state = json!({ "integrations": origins });

    let integration_credentials = environment
        .integrations
        .iter()
        .map(|(alias, binding)| {
            (
                alias,
                json!({
                    "credential": binding.source.credential,
                    "source_mtls_private_key": binding.source.mtls.as_ref().map(|mtls| &mtls.private_key),
                    "oauth_mtls_private_key": binding.source.oauth.as_ref()
                        .and_then(|endpoint| endpoint.mtls.as_ref())
                        .map(|mtls| &mtls.private_key),
                    "jwks_mtls_private_key": binding.source.jwks.as_ref()
                        .and_then(|endpoint| endpoint.mtls.as_ref())
                        .map(|mtls| &mtls.private_key),
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let credential_state = json!({ "integrations": integration_credentials });

    let integration_trust = environment
        .integrations
        .iter()
        .map(|(alias, binding)| {
            (
                alias,
                json!({
                    "allowed_private_cidrs": binding.source.allowed_private_cidrs,
                    "ca": binding.source.ca,
                    "mtls": binding.source.mtls.as_ref().map(|mtls| json!({
                        "certificate_file": mtls.certificate_file,
                        "generation": mtls.generation,
                    })),
                    "oauth": binding.source.oauth.as_ref().map(promotion_private_endpoint_trust),
                    "jwks": binding.source.jwks.as_ref().map(promotion_private_endpoint_trust),
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let trust_state = json!({
        "integrations": integration_trust,
        "relay": environment.relay,
        "oid4vci_authorization_server": environment.oid4vci.as_ref().map(|binding| json!({
            "issuer": binding.authorization_server.issuer,
        })),
        "oid4vci_registrar_clients": environment.oid4vci.as_ref()
            .map(|binding| &binding.registrar_clients),
    });
    let trust_members = environment
        .integrations
        .iter()
        .flat_map(|(alias, binding)| {
            let mut values = binding
                .source
                .allowed_private_cidrs
                .iter()
                .map(|cidr| json!(["source", alias, cidr]))
                .collect::<Vec<_>>();
            for (label, endpoint) in [
                ("oauth", binding.source.oauth.as_ref()),
                ("jwks", binding.source.jwks.as_ref()),
            ] {
                if let Some(endpoint) = endpoint {
                    values.extend(
                        endpoint
                            .allowed_private_cidrs
                            .iter()
                            .map(|cidr| json!([label, alias, cidr])),
                    );
                }
            }
            values
        })
        .chain(
            environment
                .relay
                .iter()
                .flat_map(|relay| relay.allowed_clients.iter())
                .map(|client| json!(["relay_client", client])),
        )
        .chain(
            environment
                .oid4vci
                .iter()
                .flat_map(|binding| binding.registrar_clients.iter())
                .map(|client| json!(["oid4vci_registrar_client", client])),
        )
        .collect::<Vec<_>>();

    let caller_state = environment.callers.iter().collect::<BTreeMap<_, _>>();
    let caller_members = environment
        .callers
        .iter()
        .flat_map(|(id, caller)| {
            std::iter::once(json!(["caller", id])).chain(
                caller
                    .scopes
                    .iter()
                    .map(move |scope| json!(["caller_scope", id, scope])),
            )
        })
        .collect::<Vec<_>>();

    let operational_integrations = environment
        .integrations
        .iter()
        .map(|(alias, binding)| {
            (
                alias,
                json!({
                    "rate": binding.source.rate,
                    "concurrency": binding.source.concurrency,
                    "timeout": binding.source.timeout,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let operational_state = json!({
        "integrations": operational_integrations,
        "entities": environment.entities,
        "relay_state": environment.relay_state,
        "notary_state": environment.notary_state,
        "notary_cel": environment.notary_cel,
        "issuance": environment.issuance,
        "notary_relay": environment.notary_relay,
        "oid4vci": environment.oid4vci,
        "deployment_profile": environment.deployment.profile,
        "deployment_relay_service": environment.deployment.relay.as_ref().map(|binding| &binding.service),
        "deployment_notary_service": environment.deployment.notary.as_ref().map(|binding| &binding.service),
        "oid4vci_subject": environment.oid4vci.as_ref().map(|binding| &binding.subject),
        "oid4vci_tx_code": environment.oid4vci.as_ref().map(|binding| &binding.tx_code),
    });

    let purpose_state = loaded
        .project
        .services
        .iter()
        .map(|(id, service)| (id, &service.purpose))
        .collect::<BTreeMap<_, _>>();
    let service_policy_state = loaded
        .project
        .services
        .iter()
        .map(|(id, service)| {
            (
                id,
                json!({
                    "legal_basis": service.legal_basis,
                    "consent": service.consent,
                    "access": service.access,
                    "variables": service.variables,
                    "records": {
                        "entity": service.entity,
                        "title": service.title,
                        "description": service.description,
                        "owner": service.owner,
                        "sensitivity": service.sensitivity,
                        "access_rights": service.access_rights,
                        "update_frequency": service.update_frequency,
                        "conforms_to": service.conforms_to,
                        "api": service.api,
                    },
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let service_policy_members = loaded
        .project
        .services
        .iter()
        .flat_map(|(id, service)| {
            let consent = (service.consent == ConsentDeclaration::NotRequired)
                .then(|| json!(["consent_not_required", id]));
            service
                .access
                .scopes
                .iter()
                .map(|scope| json!(["service_scope", id, scope]))
                .chain(consent)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let claim_state = loaded
        .project
        .services
        .iter()
        .map(|(service_id, service)| {
            let claims = service
                .claims
                .iter()
                .map(|(claim_id, claim)| {
                    (
                        claim_id,
                        json!({
                            "output": claim.output,
                            "cel": claim.cel,
                            "value": claim.value,
                        }),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            (
                service_id,
                json!({
                    "claims": claims,
                    "credential_profiles": service.credential_profiles,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let claim_members = loaded
        .project
        .services
        .iter()
        .flat_map(|(service_id, service)| {
            service
                .claims
                .keys()
                .map(|claim_id| json!(["claim", service_id, claim_id]))
                .chain(
                    service
                        .credential_profiles
                        .keys()
                        .map(|profile| json!(["credential_profile", service_id, profile])),
                )
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let disclosure_state = disclosure_review_profiles(&loaded.project);
    let disclosure_members = disclosure_state
        .iter()
        .flat_map(|(service_id, claims)| {
            claims.iter().flat_map(move |(claim_id, profile)| {
                profile
                    .allowed
                    .iter()
                    .map(move |mode| json!(["disclosure", service_id, claim_id, mode]))
            })
        })
        .collect::<Vec<_>>();

    let product_state = json!({ "products": products });
    let product_members = products
        .iter()
        .map(|product| json!(["product", product]))
        .collect::<Vec<_>>();

    let capability_state = loaded
        .integrations
        .iter()
        .map(|(alias, integration)| {
            let enabled = project_promotion_capability_enabled(
                alias,
                &integration.document.capability,
                environment,
            );
            (
                alias,
                json!({
                    "capability": promotion_capability_kind(&integration.document.capability),
                    "enabled": enabled,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let capability_members = capabilities
        .iter()
        .map(|capability| json!(["capability", capability]))
        .collect::<Vec<_>>();

    let ceiling_integrations = loaded
        .integrations
        .iter()
        .map(|(alias, integration)| {
            let capability_contract = match &integration.document.capability {
                CapabilityDeclaration::Http { http } => json!({
                    "operations": http.operations,
                }),
                CapabilityDeclaration::Script { script } => json!({
                    "allow": script.allow,
                    "request_headers": script.request_headers,
                    "response_headers": script.response_headers,
                    "response": script.response,
                    "signed_dci": script.signed_dci,
                    "script_digest": integration.script.as_ref().map(|(_, bytes)| sha256_uri(bytes)),
                    "module_digests": integration.script_modules.iter()
                        .map(|(_, bytes)| sha256_uri(bytes))
                        .collect::<Vec<_>>(),
                }),
                CapabilityDeclaration::Snapshot { snapshot } => json!({
                    "snapshot": snapshot,
                }),
            };
            (
                alias,
                json!({
                    "version": integration.document.version,
                    "revision": integration.document.revision,
                    "source": integration.document.source,
                    "input": integration.document.input,
                    "contract": capability_contract,
                    "outputs": integration.document.outputs,
                    "not_applicable": integration.document.not_applicable,
                    "bounds": integration.document.bounds,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let consultations = loaded
        .project
        .services
        .iter()
        .map(|(service, declaration)| (service, &declaration.consultations))
        .collect::<BTreeMap<_, _>>();
    let entity_state = loaded
        .entities
        .iter()
        .map(|(id, entity)| (id, &entity.document))
        .collect::<BTreeMap<_, _>>();
    let ceiling_state = json!({
        "integrations": ceiling_integrations,
        "consultations": consultations,
        "entities": entity_state,
    });
    let ceiling_members = loaded
        .integrations
        .iter()
        .flat_map(|(alias, integration)| {
            let mut members = vec![json!(["integration", alias])];
            members.extend(
                integration
                    .document
                    .input
                    .keys()
                    .map(|id| json!(["integration_input", alias, id])),
            );
            members.extend(
                integration
                    .document
                    .outputs
                    .keys()
                    .map(|id| json!(["integration_output", alias, id])),
            );
            if let CapabilityDeclaration::Http { http } = &integration.document.capability {
                members.extend(
                    http.operations
                        .keys()
                        .map(|id| json!(["integration_operation", alias, id])),
                );
            }
            members
        })
        .chain(loaded.entities.keys().map(|id| json!(["entity", id])))
        .chain(
            loaded
                .project
                .services
                .iter()
                .flat_map(|(service, declaration)| {
                    declaration
                        .consultations
                        .keys()
                        .map(move |consultation| json!(["consultation", service, consultation]))
                }),
        )
        .collect::<Vec<_>>();

    let field_inputs = [
        (
            PromotionChangeKind::Origin,
            PromotionFieldClassification::Sensitive,
            origin_state,
            Vec::new(),
        ),
        (
            PromotionChangeKind::CredentialBinding,
            PromotionFieldClassification::SecretReference,
            credential_state,
            Vec::new(),
        ),
        (
            PromotionChangeKind::Trust,
            PromotionFieldClassification::Sensitive,
            trust_state,
            trust_members,
        ),
        (
            PromotionChangeKind::Caller,
            PromotionFieldClassification::Sensitive,
            json!(caller_state),
            caller_members,
        ),
        (
            PromotionChangeKind::Operational,
            PromotionFieldClassification::Internal,
            operational_state,
            Vec::new(),
        ),
        (
            PromotionChangeKind::Purpose,
            PromotionFieldClassification::Internal,
            json!(purpose_state),
            Vec::new(),
        ),
        (
            PromotionChangeKind::ServicePolicy,
            PromotionFieldClassification::Internal,
            json!(service_policy_state),
            service_policy_members,
        ),
        (
            PromotionChangeKind::Claim,
            PromotionFieldClassification::Internal,
            json!(claim_state),
            claim_members,
        ),
        (
            PromotionChangeKind::Disclosure,
            PromotionFieldClassification::Internal,
            json!(disclosure_state),
            disclosure_members,
        ),
        (
            PromotionChangeKind::ProductEnablement,
            PromotionFieldClassification::Structural,
            product_state,
            product_members,
        ),
        (
            PromotionChangeKind::CapabilityEnablement,
            PromotionFieldClassification::Structural,
            json!(capability_state),
            capability_members,
        ),
        (
            PromotionChangeKind::IntegrationCeiling,
            PromotionFieldClassification::Structural,
            ceiling_state,
            ceiling_members,
        ),
    ];
    let fields = field_inputs
        .into_iter()
        .map(|(kind, classification, state, authority_members)| {
            promotion_projected_field(kind, classification, &state, authority_members)
        })
        .collect::<Result<Vec<_>>>()?;

    let projection = ProjectPromotionProjectionV1 {
        schema_version: ProjectPromotionProjectionSchemaVersion::V1,
        field_knowledge_revision,
        authoring_schemas: project_promotion_authoring_schemas(loaded, environment),
        products,
        capabilities,
        fields,
    };
    validate_project_promotion_projection(&projection, PROMOTION_FIELD_KNOWLEDGE_REVISION)
        .map_err(|error| anyhow!(error))?;
    Ok(projection)
}

fn project_promotion_authoring_schemas(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> PromotionAuthoringSchemaVersions {
    PromotionAuthoringSchemaVersions {
        project: loaded.project.version,
        environment: environment.version,
        integrations: loaded
            .integrations
            .values()
            .map(|integration| integration.document.version)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        entities: loaded
            .entities
            .values()
            .map(|entity| entity.document.version)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

fn promotion_private_endpoint_trust(binding: &PrivateEndpointBinding) -> Value {
    json!({
        "allowed_private_cidrs": binding.allowed_private_cidrs,
        "ca": binding.ca,
        "mtls": binding.mtls.as_ref().map(|mtls| json!({
            "certificate_file": mtls.certificate_file,
            "generation": mtls.generation,
        })),
        "generation": binding.generation,
    })
}

fn project_promotion_products(environment: &EnvironmentDocument) -> Vec<PromotionProjectedProduct> {
    let mut products = Vec::new();
    if environment.deployment.relay.is_some() {
        products.push(PromotionProjectedProduct::Relay);
    }
    if environment.deployment.notary.is_some() {
        products.push(PromotionProjectedProduct::Notary);
    }
    products
}

fn project_promotion_capabilities(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
) -> Vec<PromotionProjectedCapability> {
    loaded
        .integrations
        .iter()
        .filter(|(alias, integration)| {
            project_promotion_capability_enabled(
                alias,
                &integration.document.capability,
                environment,
            )
        })
        .map(|(_, integration)| promotion_capability_kind(&integration.document.capability))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn project_promotion_capability_enabled(
    alias: &str,
    capability: &CapabilityDeclaration,
    environment: &EnvironmentDocument,
) -> bool {
    match capability {
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
            environment.integrations.contains_key(alias)
        }
        CapabilityDeclaration::Snapshot { snapshot } => {
            environment.entities.contains_key(&snapshot.entity)
        }
    }
}

const fn promotion_capability_kind(
    capability: &CapabilityDeclaration,
) -> PromotionProjectedCapability {
    match capability {
        CapabilityDeclaration::Http { .. } => PromotionProjectedCapability::Http,
        CapabilityDeclaration::Script { .. } => PromotionProjectedCapability::Script,
        CapabilityDeclaration::Snapshot { .. } => PromotionProjectedCapability::Snapshot,
    }
}

fn promotion_projected_field(
    kind: PromotionChangeKind,
    classification: PromotionFieldClassification,
    state: &Value,
    authority_members: Vec<Value>,
) -> Result<PromotionProjectedField> {
    let mut authority_members = authority_members
        .iter()
        .map(digest_json)
        .collect::<Result<Vec<_>>>()?;
    authority_members.sort();
    authority_members.dedup();
    Ok(PromotionProjectedField {
        address: kind.address(),
        kind,
        classification,
        ownership: kind.expected_ownership(),
        digest: digest_json(state)?,
        authority_members,
    })
}

fn validate_promotion_field_knowledge_mapping() -> Result<String> {
    let index = knowledge::published_field_knowledge_index()
        .map_err(|error| anyhow!("published field knowledge is invalid: {error}"))?;
    let mut mapped_kinds = BTreeSet::new();
    let records = index
        .by_path()
        .iter()
        .map(|(path, field)| {
            let kind = promotion_kind_for_field_path(path);
            if let Some(kind) = kind {
                mapped_kinds.insert(kind);
                if kind.expected_ownership() != promotion_ownership_for_schema(path.schema) {
                    bail!("published field knowledge has an invalid promotion owner");
                }
            } else if path.schema != knowledge::SchemaKind::Fixture {
                bail!("published runtime field lacks a closed promotion mapping");
            }
            Ok(json!({
                "schema": path.schema,
                "pointer": path.pointer,
                "path_kind": field.path_kind,
                "semantic_owner": field.semantic_owner,
                "human_owner": field.human_owner,
                "sensitivity": field.sensitivity,
                "products": field.products,
                "introduced_in": field.introduced_in,
                "availability": field.availability,
                "stability": field.stability,
                "migration": field.migration,
                "consumers": field.consumers,
                "generated_artifacts": field.generated_artifacts,
                "review_classes": field.review_classes,
                "semantic_rules": field.semantic_rules,
                "promotion_kind": kind,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    if mapped_kinds != PromotionChangeKind::ALL.into_iter().collect() {
        bail!("published field knowledge does not exercise every closed promotion mapping");
    }
    let revision = digest_json(&Value::Array(records))?;
    if revision != PROMOTION_FIELD_KNOWLEDGE_REVISION {
        bail!(
            "promotion field-knowledge mapping revision requires review: expected {}, observed {}",
            PROMOTION_FIELD_KNOWLEDGE_REVISION,
            revision
        );
    }
    Ok(revision)
}

fn promotion_ownership_for_schema(schema: knowledge::SchemaKind) -> PromotionFieldOwnership {
    match schema {
        knowledge::SchemaKind::Environment => PromotionFieldOwnership::EnvironmentOwned,
        knowledge::SchemaKind::Project
        | knowledge::SchemaKind::Integration
        | knowledge::SchemaKind::Entity => PromotionFieldOwnership::ReviewedProjectOwned,
        knowledge::SchemaKind::Fixture => PromotionFieldOwnership::Unclassified,
    }
}

fn promotion_kind_for_field_path(path: &knowledge::FieldPath) -> Option<PromotionChangeKind> {
    use knowledge::SchemaKind;
    use PromotionChangeKind as Kind;

    let pointer = path.pointer.as_str();
    match path.schema {
        SchemaKind::Fixture => None,
        SchemaKind::Entity => Some(Kind::ServicePolicy),
        SchemaKind::Integration => Some(Kind::IntegrationCeiling),
        SchemaKind::Environment => {
            let integration_field = pointer.contains("/integrations")
                || pointer.contains("/$defs/integration")
                || pointer.contains("/$defs/source")
                || pointer.contains("/$defs/credential")
                || pointer.contains("/$defs/endpoint")
                || pointer.contains("/$defs/ca")
                || pointer.contains("/$defs/mtls")
                || pointer.contains("/$defs/privateCidrs")
                || pointer.contains("/$defs/origin");
            if pointer.contains("/callers") {
                Some(Kind::Caller)
            } else if integration_field
                && (pointer.contains("/$defs/credential")
                    || pointer.contains("credential")
                    || pointer.contains("private_key"))
            {
                Some(Kind::CredentialBinding)
            } else if integration_field
                && (pointer.contains("origin")
                    || pointer.contains("_url")
                    || pointer.contains("base_url"))
            {
                Some(Kind::Origin)
            } else if pointer.contains("allowed_private_cidrs")
                || pointer.contains("/$defs/privateCidrs")
                || pointer.contains("/ca")
                || pointer.contains("/mtls")
                || pointer.contains("audience")
                || pointer.contains("allowed_clients")
                || pointer.contains("registrar_clients")
                || pointer.contains("/issuer")
            {
                Some(Kind::Trust)
            } else if pointer.ends_with("/properties/relay")
                || pointer.ends_with("/properties/notary")
            {
                Some(Kind::ProductEnablement)
            } else if integration_field {
                Some(Kind::CapabilityEnablement)
            } else {
                Some(Kind::Operational)
            }
        }
        SchemaKind::Project => {
            if pointer.contains("/purpose") {
                Some(Kind::Purpose)
            } else if pointer.contains("/disclosure") {
                Some(Kind::Disclosure)
            } else if pointer.contains("/claims") || pointer.contains("/credential_profiles") {
                Some(Kind::Claim)
            } else if pointer.contains("/integrations")
                || pointer.contains("/entities")
                || pointer.contains("/consultations")
            {
                Some(Kind::IntegrationCeiling)
            } else {
                Some(Kind::ServicePolicy)
            }
        }
    }
}

fn digest_json(value: &Value) -> Result<String> {
    Ok(sha256_uri(
        &canonicalize_json(value).context("failed to canonicalize semantic review input")?,
    ))
}

fn validate_project_shape(project: &RegistryProject) -> Result<()> {
    if project.version != 1 {
        bail!("registry-stack.yaml version must be 1");
    }
    validate_stable_id(&project.registry.id, "registry.id")?;
    if let Some(starter) = &project.starter {
        validate_stable_id(&starter.id, "starter.id")?;
        validate_token(&starter.release, "starter.release", 64)?;
        if starter.content_digest.len() != 71
            || !starter.content_digest.starts_with("sha256:")
            || !starter.content_digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("starter.content_digest must use lowercase sha256:<64-hex> syntax");
        }
    }
    if project.integrations.len() > 16 {
        bail!("project must declare no more than 16 integrations");
    }
    if project.entities.len() > 32 {
        bail!("project must declare no more than 32 entities");
    }
    if project.integrations.is_empty() && project.entities.is_empty() && project.services.is_empty()
    {
        bail!("project must declare at least one integration, entity, or service");
    }
    if project.services.len() > 32 {
        bail!("project must declare no more than 32 services");
    }
    for (alias, reference) in &project.integrations {
        validate_stable_id(alias, "integration alias")?;
        validate_relative_authored_path(&reference.file)?;
    }
    for (alias, reference) in &project.entities {
        validate_stable_id(alias, "entity alias")?;
        validate_relative_authored_path(&reference.file)?;
        let expected = PathBuf::from("entities").join(format!("{alias}.yaml"));
        if reference.file != expected {
            bail!("entity {alias} must reference entities/{alias}.yaml");
        }
    }
    let mut project_claim_ids = BTreeSet::new();
    let mut published_entities = BTreeSet::new();
    let mut project_attribute_release_profiles = BTreeSet::new();
    for (service_id, service) in &project.services {
        validate_stable_id(service_id, "service id")?;
        match service.kind {
            ServiceKind::RecordsApi => {
                if service.subject_type.is_some()
                    || service.version != 0
                    || !service.purpose.is_empty()
                    || !service.legal_basis.is_empty()
                    || !service.access.scopes.is_empty()
                    || !service.variables.is_empty()
                    || !service.consultations.is_empty()
                    || !service.claims.is_empty()
                    || !service.credential_profiles.is_empty()
                {
                    bail!("records_api service cannot declare evidence-service fields");
                }
                let entity = service
                    .entity
                    .as_deref()
                    .ok_or_else(|| anyhow!("records_api service requires an entity"))?;
                validate_stable_id(entity, "records_api entity")?;
                if !project.entities.contains_key(entity) {
                    bail!("records_api service references an unknown entity");
                }
                if !published_entities.insert(entity) {
                    bail!("one entity cannot be published by multiple records_api services");
                }
                if service.api.is_none() {
                    bail!("records_api service requires api publication policy");
                }
                for (profile_id, profile) in &service
                    .api
                    .as_ref()
                    .expect("records API policy was checked")
                    .attribute_release_profiles
                {
                    if !project_attribute_release_profiles
                        .insert((profile_id.as_str(), profile.version.as_str()))
                    {
                        bail!(
                            "attribute release profile id and version pairs must be unique across the project"
                        );
                    }
                }
                continue;
            }
            ServiceKind::Evidence => {
                if service.entity.is_some()
                    || service.title.is_some()
                    || service.description.is_some()
                    || service.owner.is_some()
                    || service.sensitivity.is_some()
                    || service.access_rights.is_some()
                    || service.update_frequency.is_some()
                    || !service.conforms_to.is_empty()
                    || service.api.is_some()
                {
                    bail!("evidence services cannot declare records_api fields");
                }
            }
        }
        if service.version == 0 {
            bail!("service version must be positive");
        }
        validate_token(&service.purpose, "service purpose", 256)?;
        validate_token(&service.legal_basis, "service legal_basis", 128)?;
        if service.consent == ConsentDeclaration::Required {
            bail!("consent: required is unavailable until sealed consent verification lands");
        }
        validate_scopes(&service.access.scopes)?;
        if service.consultations.len() > 16 {
            bail!("service consultations must contain no more than 16 entries");
        }
        if service.claims.is_empty() || service.claims.len() > MAX_CLAIMS {
            bail!("evidence service claims must contain between one and 64 entries");
        }
        for (name, consultation) in &service.consultations {
            validate_stable_id(name, "consultation name")?;
            if !project.integrations.contains_key(&consultation.integration) {
                bail!("consultation references an unknown integration");
            }
            if !(1..=16).contains(&consultation.input.len()) {
                bail!(
                    "consultation input must contain between one and sixteen typed input mappings"
                );
            }
            for mapping in consultation.input.values() {
                validate_request_mapping(mapping)?;
            }
        }
        for (variable, declaration) in &service.variables {
            validate_stable_id(variable, "request variable")?;
            if declaration.from != format!("request.variables.{variable}")
                || declaration.value_type != OutputType::Date
            {
                bail!("v1 request variables must be exact declared full-date mappings");
            }
        }
        for (claim_id, claim) in &service.claims {
            validate_stable_id(claim_id, "claim id")?;
            if !project_claim_ids.insert(claim_id) {
                bail!("Notary claim ids must be unique across project services");
            }
            if claim.output.is_some() == claim.cel.is_some() {
                bail!("each claim must declare exactly one of output or cel");
            }
            match inferred_claim_evidence(service, claim)? {
                ClaimEvidence::RegistryBacked => {
                    if service.consultations.is_empty() {
                        bail!("registry-backed claims require a Relay consultation");
                    }
                }
                ClaimEvidence::SelfAttested => {
                    if claim.output.is_some() {
                        bail!("source-free claims cannot reference Relay outputs");
                    }
                    if claim.value.is_none() {
                        bail!("source-free claims require an explicit value contract");
                    }
                    let roots = cel_member_roots(
                        claim
                            .cel
                            .as_deref()
                            .expect("claim source shape was checked"),
                    )?;
                    if service
                        .consultations
                        .keys()
                        .any(|name| roots.contains(name.as_str()))
                    {
                        bail!("source-free claims cannot depend on Relay consultations");
                    }
                }
            }
            if let Some(value) = &claim.value {
                if value.value_type == OutputType::String {
                    let Some(max_bytes) = value.max_bytes else {
                        bail!("string claim value contracts require max_bytes");
                    };
                    if !(1..=registry_notary_core::MAX_CLAIM_VALUE_STRING_BYTES_V1)
                        .contains(&max_bytes)
                    {
                        bail!(
                            "string claim value max_bytes must be between 1 and {}",
                            registry_notary_core::MAX_CLAIM_VALUE_STRING_BYTES_V1
                        );
                    }
                }
                if value.value_type != OutputType::String && value.max_bytes.is_some() {
                    bail!("only string claim value contracts may declare max_bytes");
                }
            }
            validate_disclosure(&claim.disclosure)?;
        }
        for (credential_id, credential) in &service.credential_profiles {
            if credential.claims.is_empty() {
                bail!("credential claim allow-list must not be empty");
            }
            for claim_id in &credential.claims {
                let claim = service
                    .claims
                    .get(claim_id)
                    .ok_or_else(|| anyhow!("credential references an unknown claim"))?;
                if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
                    bail!(
                        "credential profile {service_id}.{credential_id} selects source-free claim {claim_id}; credential profiles require registry-backed claim evidence"
                    );
                }
            }
        }
    }
    Ok(())
}

fn inferred_claim_evidence(
    service: &ServiceDeclaration,
    claim: &ClaimDeclaration,
) -> Result<ClaimEvidence> {
    if claim.output.is_some() {
        return Ok(ClaimEvidence::RegistryBacked);
    }
    let roots = claim
        .cel
        .as_deref()
        .map(cel_member_roots)
        .transpose()?
        .unwrap_or_default();
    Ok(
        if service
            .consultations
            .keys()
            .any(|name| roots.contains(name.as_str()))
        {
            ClaimEvidence::RegistryBacked
        } else {
            ClaimEvidence::SelfAttested
        },
    )
}

fn validate_entity_definition(entity: &EntityDefinition) -> Result<()> {
    if entity.version != 1 || entity.revision == 0 {
        bail!("entity version must be 1 and revision must be positive");
    }
    validate_stable_id(&entity.id, "entity id")?;
    if entity.id.len() > 45 || !is_lower_snake_id(&entity.id) {
        bail!("entity id exceeds the shared materialization provider bound");
    }
    validate_stable_id(&entity.primary_key, "entity primary_key")?;
    if entity.schema.additional_properties {
        bail!("entity schema must set additionalProperties: false");
    }
    if entity.schema.properties.is_empty() || entity.schema.properties.len() > 256 {
        bail!("entity schema properties must contain between one and 256 entries");
    }
    let properties = entity.schema.properties.keys().collect::<BTreeSet<_>>();
    let required = entity.schema.required.iter().collect::<BTreeSet<_>>();
    if required.len() != entity.schema.required.len() || required != properties {
        bail!("entity schema must require every declared property exactly once");
    }
    if !entity.schema.properties.contains_key(&entity.primary_key) {
        bail!("entity primary_key must reference a declared property");
    }
    for (name, field) in &entity.schema.properties {
        validate_stable_id(name, "entity property")?;
        if !is_lower_snake_id(name) {
            bail!("entity properties must use Relay lower-snake ids");
        }
        let (_, nullable, _) = entity_output_contract(name, field)?;
        if name == &entity.primary_key && nullable {
            bail!("entity primary_key must be non-nullable");
        }
    }
    parse_entity_generation_bytes(&entity.materialization.max_bytes)
        .context("entity materialization exceeds the v1 bounds")?;
    if entity.materialization.max_records == 0
        || entity.materialization.max_records > 100_000_000
        || !(1..=16).contains(&entity.materialization.retain_generations)
    {
        bail!("entity materialization exceeds the v1 bounds");
    }
    if entity.materialization.refresh != "manual" {
        parse_materialization_refresh_ms(&entity.materialization.refresh)
            .context("entity materialization refresh is invalid")?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordsScopeCollisionKind {
    RecordApi,
    AttributeRelease,
}

#[derive(Debug, PartialEq, Eq)]
struct RecordsScopeCollision {
    kind: RecordsScopeCollisionKind,
    field: String,
    conflicts_with: String,
}

impl std::fmt::Display for RecordsScopeCollision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} must differ from {}; effective records authorization scopes must be unique",
            self.field, self.conflicts_with
        )
    }
}

fn effective_records_api_scopes(
    service_id: &str,
    api: &RecordsApiDeclaration,
    entity: &EntityDefinition,
) -> Vec<(String, String)> {
    let mut scopes = vec![
        (
            format!("services.{service_id}.api.scopes.metadata"),
            api.scopes.metadata.clone(),
        ),
        (
            format!("services.{service_id}.api.scopes.rows"),
            api.scopes.rows.clone(),
        ),
        (
            format!("services.{service_id}.api.scopes.aggregate"),
            api.scopes
                .aggregate
                .clone()
                .unwrap_or_else(|| format!("{}:aggregate", entity.id)),
        ),
    ];
    if let Some(scope) = &api.scopes.evidence_verification {
        scopes.push((
            format!("services.{service_id}.api.scopes.evidence_verification"),
            scope.clone(),
        ));
    }
    scopes
}

fn records_scope_collision(
    service_id: &str,
    api: &RecordsApiDeclaration,
    entity: &EntityDefinition,
) -> Option<RecordsScopeCollision> {
    let effective_scopes = effective_records_api_scopes(service_id, api, entity);
    let mut fields_by_scope = BTreeMap::new();
    for (field, scope) in &effective_scopes {
        if let Some(conflicts_with) = fields_by_scope.insert(scope.as_str(), field.as_str()) {
            return Some(RecordsScopeCollision {
                kind: RecordsScopeCollisionKind::RecordApi,
                field: field.clone(),
                conflicts_with: conflicts_with.to_string(),
            });
        }
    }

    // Profiles intentionally share the entity-bound identity-release privilege.
    // That privilege must never alias a record API privilege, or a key granted
    // metadata, aggregate, row, or verification access could release attributes.
    for (profile_id, profile) in &api.attribute_release_profiles {
        if let Some((conflicts_with, _)) = effective_scopes
            .iter()
            .find(|(_, scope)| scope == &profile.release_scope)
        {
            return Some(RecordsScopeCollision {
                kind: RecordsScopeCollisionKind::AttributeRelease,
                field: format!(
                    "services.{service_id}.api.attribute_release_profiles.{profile_id}.release_scope"
                ),
                conflicts_with: conflicts_with.clone(),
            });
        }
    }
    None
}

fn project_records_scope_collision(
    project: &RegistryProject,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
) -> Option<RecordsScopeCollision> {
    project.services.iter().find_map(|(service_id, service)| {
        if service.kind != ServiceKind::RecordsApi {
            return None;
        }
        let api = service.api.as_ref()?;
        let entity = entities.get(service.entity.as_deref()?)?;
        records_scope_collision(service_id, api, &entity.document)
    })
}

fn validate_records_service(
    service_id: &str,
    service: &ServiceDeclaration,
    entity: &EntityDefinition,
) -> Result<()> {
    let api = service
        .api
        .as_ref()
        .ok_or_else(|| anyhow!("records_api service requires api publication policy"))?;
    for (label, value) in [
        ("records title", service.title.as_deref()),
        ("records description", service.description.as_deref()),
        ("records owner", service.owner.as_deref()),
    ] {
        if let Some(value) = value {
            validate_authored_text(value, label)?;
        }
    }
    if service.conforms_to.len() > 32
        || service.conforms_to.iter().collect::<BTreeSet<_>>().len() != service.conforms_to.len()
    {
        bail!("records conforms_to must contain at most 32 unique entries");
    }
    for value in &service.conforms_to {
        validate_authored_text(value, "records conforms_to")?;
    }
    for scope in [
        Some(&api.scopes.metadata),
        Some(&api.scopes.rows),
        api.scopes.aggregate.as_ref(),
        api.scopes.evidence_verification.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_token(scope, "records scope", 128)?;
        if scope.split_once(':').map(|(dataset, _)| dataset) != Some(entity.id.as_str()) {
            bail!("records scopes must use their entity id namespace");
        }
    }
    if let Some(collision) = records_scope_collision(service_id, api, entity)
        .filter(|collision| collision.kind == RecordsScopeCollisionKind::RecordApi)
    {
        bail!("{collision}");
    }
    if api.pagination.default_limit == 0
        || api.pagination.max_limit == 0
        || api.pagination.default_limit > api.pagination.max_limit
        || api.pagination.max_limit > 10_000
    {
        bail!("records pagination limits are invalid");
    }
    if api.purposes.len() > 32
        || api.purposes.iter().collect::<BTreeSet<_>>().len() != api.purposes.len()
        || api.filters.len() > 256
        || api.relationships.len() > 64
        || api.aggregates.len() > 64
        || api.attribute_release_profiles.len() > 16
    {
        bail!("records publication policy exceeds the v1 collection bounds");
    }
    for purpose in &api.purposes {
        validate_token(purpose, "records purpose", 256)?;
    }
    let field_names = entity
        .schema
        .properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if api.projection.is_empty()
        || api.projection.len() > 256
        || api.projection.iter().collect::<BTreeSet<_>>().len() != api.projection.len()
        || api.required_principal_filters.len() > 16
        || api
            .required_principal_filters
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != api.required_principal_filters.len()
        || api
            .projection
            .iter()
            .any(|field| !field_names.contains(field.as_str()))
    {
        bail!("records projection must be a non-empty unique entity field subset");
    }
    validate_record_attribute_release_profiles(service_id, api, entity, &field_names)?;
    for (field, operators) in &api.filters {
        if !field_names.contains(field.as_str()) || operators.is_empty() {
            bail!("records filters must name declared fields and at least one operator");
        }
        if operators.iter().collect::<BTreeSet<_>>().len() != operators.len() {
            bail!("records filter operators must be unique");
        }
    }
    for field in &api.required_principal_filters {
        if !field_names.contains(field.as_str()) || !api.filters.contains_key(field) {
            bail!("required principal filters must be allow-listed records fields");
        }
    }
    for (name, relationship) in &api.relationships {
        validate_stable_id(name, "records relationship")?;
        if !is_lower_snake_id(name) {
            bail!("records relationships must use Relay lower-snake ids");
        }
        validate_stable_id(&relationship.target, "records relationship target")?;
        if !field_names.contains(relationship.foreign_key.as_str()) {
            bail!("records relationship foreign_key must be a declared field");
        }
    }
    for (id, aggregate) in &api.aggregates {
        validate_stable_id(id, "records aggregate")?;
        if !is_lower_snake_id(id) {
            bail!("records aggregates must use Relay lower-snake ids");
        }
        if (aggregate.measures.is_empty() && aggregate.indicators.is_empty())
            || aggregate.disclosure_control.min_group_size == 0
        {
            bail!(
                "records aggregate requires measures or indicators and positive disclosure control"
            );
        }
        for field in aggregate
            .group_by
            .iter()
            .chain(&aggregate.default_group_by)
            .chain(aggregate.temporal_field.iter())
        {
            if !field_names.contains(field.as_str()) {
                bail!("records aggregate fields must name declared fields");
            }
        }
        for dimension in &aggregate.dimensions {
            validate_stable_id(&dimension.id, "records aggregate dimension")?;
            if !is_lower_snake_id(&dimension.id) {
                bail!("records aggregate dimensions must use Relay lower-snake ids");
            }
            if !field_names.contains(dimension.field.as_str()) {
                bail!("records aggregate dimension must name a declared field");
            }
        }
        for indicator in &aggregate.indicators {
            validate_stable_id(&indicator.id, "records aggregate indicator")?;
            if !is_lower_snake_id(&indicator.id) {
                bail!("records aggregate indicators must use Relay lower-snake ids");
            }
            if !field_names.contains(indicator.column.as_str()) {
                bail!("records aggregate indicator must name a declared field");
            }
        }
        for measure in &aggregate.measures {
            validate_stable_id(&measure.name, "records aggregate measure")?;
            if !is_lower_snake_id(&measure.name) {
                bail!("records aggregate measures must use Relay lower-snake ids");
            }
            if !field_names.contains(measure.column.as_str()) {
                bail!("records aggregate measure must name a declared field");
            }
        }
        for (field, operators) in &aggregate.allowed_filters {
            if !field_names.contains(field.as_str()) || operators.is_empty() {
                bail!("records aggregate filters must name declared fields");
            }
        }
        for field in &aggregate.required_principal_filters {
            if !aggregate.allowed_filters.contains_key(field) {
                bail!("records aggregate principal filters must be allow-listed");
            }
        }
        if aggregate
            .joins
            .iter()
            .any(|join| !api.relationships.contains_key(join))
        {
            bail!("records aggregate joins must name declared relationships");
        }
    }
    validate_record_standards(api, &field_names)?;
    Ok(())
}

fn validate_record_attribute_release_profiles(
    service_id: &str,
    api: &RecordsApiDeclaration,
    entity: &EntityDefinition,
    fields: &BTreeSet<&str>,
) -> Result<()> {
    if !api.attribute_release_profiles.is_empty() && !api.required_principal_filters.is_empty() {
        bail!(
            "attribute release profiles cannot use required principal filters because the caller-supplied subject cannot satisfy a principal-bound filter"
        );
    }
    if !api.attribute_release_profiles.is_empty() && api.pagination.max_limit < 2 {
        bail!(
            "attribute release profiles require records pagination max_limit of at least 2 to detect ambiguous subjects"
        );
    }
    let projected = api
        .projection
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (profile_id, profile) in &api.attribute_release_profiles {
        if !is_record_release_profile_id(profile_id) {
            bail!("attribute release profile id must match [a-z][a-z0-9_-]{{0,95}}");
        }
        validate_release_version(&profile.version, "attribute release profile version")?;
        if let Some(title) = &profile.title {
            validate_authored_text(title, "attribute release profile title")?;
        }
        if let Some(description) = &profile.description {
            validate_authored_text(description, "attribute release profile description")?;
        }
        validate_header_token(&profile.purpose, "attribute release profile purpose", 256)?;
        if !api.purposes.contains(&profile.purpose) {
            bail!("attribute release profile purpose must be a records API permitted purpose");
        }
        let expected_scope = format!("{}:identity_release", entity.id);
        if profile.release_scope != expected_scope {
            bail!(
                "attribute release profile release_scope must be the entity-bound {expected_scope} scope"
            );
        }
        if let Some(collision) = records_scope_collision(service_id, api, entity).filter(
            |collision| {
                collision.kind == RecordsScopeCollisionKind::AttributeRelease
                    && collision.field
                        == format!(
                            "services.{service_id}.api.attribute_release_profiles.{profile_id}.release_scope"
                        )
            },
        ) {
            bail!("{collision}");
        }
        validate_token(
            &profile.subject.id_type,
            "attribute release subject id_type",
            64,
        )?;
        if !fields.contains(profile.subject.source_field.as_str())
            || !projected.contains(profile.subject.source_field.as_str())
        {
            bail!("attribute release subject source_field must be an explicitly projected entity field");
        }
        validate_record_release_expression(
            &profile.release_conditions.expression,
            "attribute release condition",
        )?;
        if profile.claims.is_empty() || profile.claims.len() > 32 {
            bail!("attribute release claims must contain between one and 32 entries");
        }
        let mut has_required_claim = false;
        for (claim_name, claim) in &profile.claims {
            if claim_name.len() > 64 || !is_lower_snake_id(claim_name) {
                bail!("attribute release claim names must use bounded lower-snake identifiers");
            }
            if claim.source_field.is_some() == claim.expression.is_some() {
                bail!(
                    "attribute release claims must declare exactly one of source_field or expression"
                );
            }
            if let Some(source_field) = &claim.source_field {
                if !fields.contains(source_field.as_str())
                    || !projected.contains(source_field.as_str())
                {
                    bail!(
                        "attribute release claim source_field must be an explicitly projected entity field"
                    );
                }
            }
            if let Some(expression) = &claim.expression {
                validate_record_release_expression(expression, "attribute release claim")?;
            }
            has_required_claim |= claim.required;
        }
        if !has_required_claim {
            bail!("attribute release profiles require at least one required claim");
        }
    }
    Ok(())
}

fn validate_record_release_expression(
    expression: &RecordAttributeReleaseExpression,
    label: &str,
) -> Result<()> {
    if expression.cel.is_empty() || expression.cel.len() > 4096 {
        bail!("{label} CEL must contain between one and 4096 bytes");
    }
    let roots =
        cel_member_roots(&expression.cel).with_context(|| format!("invalid {label} CEL"))?;
    if roots != BTreeSet::from(["source".to_string()]) {
        bail!("{label} CEL may reference only the projected source object");
    }
    registry_relay::attribute_release::validate_release_expression(&expression.cel)
        .map_err(|_| anyhow!("{label} CEL failed to compile"))?;
    Ok(())
}

fn is_record_release_profile_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 96
        && matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn validate_authored_text(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 2048
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        bail!("{label} must be non-empty, bounded, trimmed text without control characters");
    }
    Ok(())
}

fn is_lower_snake_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn validate_record_standards(api: &RecordsApiDeclaration, fields: &BTreeSet<&str>) -> Result<()> {
    let projected = api
        .projection
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    match &api.standards.ogc_features {
        RecordStandard::Disabled(false) => {}
        RecordStandard::Disabled(true) => {
            bail!("ogc_features: true requires an explicit spatial configuration")
        }
        RecordStandard::Enabled(spatial) => {
            let mut referenced = Vec::new();
            match &spatial.geometry {
                RecordSpatialGeometry::Point {
                    longitude_field,
                    latitude_field,
                    ..
                } => referenced.extend([longitude_field.as_str(), latitude_field.as_str()]),
                RecordSpatialGeometry::Geojson { field, .. }
                | RecordSpatialGeometry::Wkt { field, .. }
                | RecordSpatialGeometry::Wkb { field, .. } => referenced.push(field),
            }
            if let Some(bbox) = &spatial.bbox_fields {
                referenced.extend([
                    bbox.min_x.as_str(),
                    bbox.min_y.as_str(),
                    bbox.max_x.as_str(),
                    bbox.max_y.as_str(),
                ]);
            }
            if let Some(datetime) = &spatial.datetime_field {
                referenced.push(datetime);
            }
            if referenced.iter().any(|field| !fields.contains(*field)) {
                bail!("OGC spatial configuration must use declared logical fields");
            }
            if referenced.iter().any(|field| !projected.contains(*field)) {
                bail!("OGC spatial configuration fields must be explicitly projected");
            }
        }
    }
    match &api.standards.sp_dci {
        RecordStandard::Disabled(false) => {}
        RecordStandard::Disabled(true) => {
            bail!("sp_dci: true requires an explicit registry mapping")
        }
        RecordStandard::Enabled(spdci) => {
            validate_stable_id(&spdci.registry, "SP DCI registry id")?;
            if spdci
                .identifiers
                .values()
                .chain(spdci.expression_fields.values())
                .chain(spdci.response_fields.values())
                .any(|field| !fields.contains(field.as_str()))
            {
                bail!("SP DCI mapping must use declared logical fields");
            }
            if spdci
                .identifiers
                .values()
                .chain(spdci.expression_fields.values())
                .chain(spdci.response_fields.values())
                .any(|field| !projected.contains(field.as_str()))
            {
                bail!("SP DCI mapping fields must be explicitly projected");
            }
            if spdci
                .identifiers
                .values()
                .chain(spdci.expression_fields.values())
                .any(|field| !api.filters.contains_key(field.as_str()))
            {
                bail!("SP DCI identifier and expression fields must be explicitly filterable");
            }
        }
    }
    Ok(())
}

fn validate_project_entity_links(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
) -> Result<()> {
    for (service_id, service) in project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::RecordsApi)
    {
        let entity_id = service
            .entity
            .as_deref()
            .ok_or_else(|| anyhow!("records_api service entity is absent"))?;
        let entity = &entities
            .get(entity_id)
            .ok_or_else(|| anyhow!("records_api service references an unknown entity"))?
            .document;
        validate_records_service(service_id, service, entity)?;
    }
    for loaded in integrations.values() {
        let CapabilityDeclaration::Snapshot { snapshot } = &loaded.document.capability else {
            continue;
        };
        let definition = entities
            .get(&snapshot.entity)
            .ok_or_else(|| anyhow!("snapshot references an unknown entity"))?;
        if snapshot.exact.iter().any(|(field, input)| {
            !definition.document.schema.properties.contains_key(field)
                || !loaded.document.input.contains_key(input)
        }) {
            bail!("snapshot exact mappings must bind entity properties to integration inputs");
        }
        let projected = loaded
            .document
            .outputs
            .values()
            .filter_map(snapshot_output_field)
            .collect::<BTreeSet<_>>();
        if projected.is_empty()
            || projected
                .iter()
                .any(|field| !definition.document.schema.properties.contains_key(*field))
        {
            bail!("snapshot projection must be a non-empty entity property subset");
        }
        for name in projected {
            let field = &definition.document.schema.properties[name];
            let output = loaded
                .document
                .outputs
                .get(name)
                .ok_or_else(|| anyhow!("snapshot logical field is absent"))?;
            let (expected_type, expected_nullable, _) = entity_output_contract(name, field)?;
            if expected_type != output.output_type || expected_nullable != output.nullable {
                bail!("snapshot outputs must preserve entity field type and nullability");
            }
        }
    }
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::RecordsApi)
    {
        for relationship in service
            .api
            .as_ref()
            .expect("records service shape was validated")
            .relationships
            .values()
        {
            if !entities.contains_key(&relationship.target) {
                bail!("records relationship references an unknown entity");
            }
        }
    }
    Ok(())
}

fn validate_service_integration_links(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
) -> Result<()> {
    for (service_id, service) in project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::Evidence)
    {
        for (consultation_name, consultation) in &service.consultations {
            let integration = &integrations[&consultation.integration].document;
            if integration.outputs.len()
                > registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1
            {
                bail!(
                    "service {service_id} consultation {consultation_name} integration outputs must contain no more than {} entries",
                    registry_notary_core::MAX_RELAY_OUTPUT_OBJECT_FIELDS_V1
                );
            }
            if consultation.input.keys().ne(integration.input.keys()) {
                bail!("consultation input must bind the integration input set exactly");
            }
            if consultation.input.values().collect::<BTreeSet<_>>().len()
                != consultation.input.len()
            {
                bail!("consultation target mappings must be injective");
            }
        }
        for (claim_id, claim) in &service.claims {
            let Some(expression) = claim.cel.as_deref() else {
                continue;
            };
            if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
                continue;
            }
            let references = cel_references(expression)
                .with_context(|| format!("invalid CEL for service {service_id} claim {claim_id}"))?;
            if references.uses_index {
                bail!(
                    "service {service_id} claim {claim_id} registry-backed CEL cannot use index access"
                );
            }
            for (consultation_name, consultation) in &service.consultations {
                let Some(members) = references.first_level_members.get(consultation_name) else {
                    continue;
                };
                let integration = &integrations[&consultation.integration].document;
                for member in members {
                    if integration.outputs.get(member).is_some_and(|output| {
                        matches!(output.output_type, OutputType::Object | OutputType::Array)
                    }) {
                        bail!(
                            "service {service_id} claim {claim_id} CEL cannot reference structured consultation output {consultation_name}.{member}"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_fixture_inputs(
    alias: &str,
    integration: &IntegrationDocument,
    fixtures: &[(PathBuf, FixtureDocument)],
) -> Result<()> {
    let mut fixture_names = BTreeSet::new();
    for (path, fixture) in fixtures {
        if !fixture_names.insert(fixture.name.as_str()) {
            bail!("fixture names must be unique within an integration");
        }
        if fixture.name.is_empty() || fixture.name.len() > 256 {
            bail!("fixture name must contain between one and 256 bytes");
        }
        if fixture.classification != AuthoredFixtureClassification::Synthetic {
            bail!(
                "fixture {} must declare classification: synthetic",
                fixture.name
            );
        }
        if fixture.interactions.is_empty() || fixture.interactions.len() > 16 {
            bail!(
                "fixture {} must contain between one and sixteen interactions",
                fixture.name
            );
        }
        if fixture.input.keys().ne(integration.input.keys()) {
            bail!(
                "fixture {} must bind every {alias} input exactly once",
                fixture.name
            );
        }
        for (name, declaration) in &integration.input {
            validate_fixture_input_value(name, declaration, &fixture.input[name]).with_context(
                || {
                    format!(
                        "fixture file {} at input.{name}; correct the value to satisfy integration {alias} input.{name}",
                        path.display()
                    )
                },
            )?;
        }
        for (index, interaction) in fixture.interactions.iter().enumerate() {
            validate_fixture_request_expectation(&fixture.name, index, &interaction.expect)?;
            match &interaction.respond {
                FixtureSourceResponse::Http {
                    status,
                    headers,
                    body,
                } => {
                    if !(100..=599).contains(status) {
                        bail!(
                            "fixture {} interaction {} has an invalid response status",
                            fixture.name,
                            index + 1
                        );
                    }
                    validate_fixture_headers(headers, "response")?;
                    if serde_json::to_vec(body)?.len() > 8 * 1024 * 1024 {
                        bail!(
                            "fixture {} interaction {} response body exceeds 8 MiB",
                            fixture.name,
                            index + 1
                        );
                    }
                }
                FixtureSourceResponse::Timeout { timeout } => {
                    parse_fixture_timeout_ms(timeout)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_fixture_request_expectation(
    fixture_name: &str,
    index: usize,
    request: &FixtureRequestExpectation,
) -> Result<()> {
    if request.path.is_empty()
        || request.path.len() > 4096
        || !request.path.starts_with('/')
        || request.path.contains(['?', '#', '\\'])
        || request
            .path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        bail!(
            "fixture {fixture_name} interaction {} has a non-canonical request path",
            index + 1
        );
    }
    if request.method == ReadMethod::Get && request.body.is_some() {
        bail!("fixture GET request expectations cannot contain a body");
    }
    if request.query.len() > 64 || request.headers.len() > 32 {
        bail!("fixture request expectation exceeds its component bound");
    }
    validate_fixture_headers(&request.headers, "request")?;
    for (name, value) in &request.query {
        if name.is_empty() || name.len() > 256 || !fixture_query_value_is_bounded(value) {
            bail!("fixture request query contains an invalid bounded value");
        }
    }
    if let Some(body) = &request.body {
        validate_generated_fixture_matchers(body, false)?;
        if serde_json::to_vec(body)?.len() > 1024 * 1024 {
            bail!("fixture request expectation body exceeds 1 MiB");
        }
    }
    Ok(())
}

fn validate_fixture_headers(headers: &BTreeMap<String, String>, field: &str) -> Result<()> {
    let mut folded = BTreeSet::new();
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'-'
                }
            })
            || value.len() > 8192
            || !folded.insert(name.to_ascii_lowercase())
        {
            bail!("fixture {field} headers violate the closed bounded contract");
        }
    }
    Ok(())
}

fn fixture_query_value_is_bounded(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => value.len() <= 8192,
        Value::Array(values) => {
            values.len() <= 64 && values.iter().all(fixture_query_value_is_bounded)
        }
        Value::Object(_) => false,
    }
}

fn validate_generated_fixture_matchers(value: &Value, inside_matcher: bool) -> Result<()> {
    match value {
        Value::Array(values) => {
            for value in values {
                validate_generated_fixture_matchers(value, false)?;
            }
        }
        Value::Object(object) => {
            if let Some(generated) = object.get("generated") {
                if inside_matcher
                    || object.len() != 1
                    || !matches!(
                        generated.as_str(),
                        Some("dci-correlation" | "rfc3339-timestamp")
                    )
                {
                    bail!("fixture generated matcher must be one confined supported leaf");
                }
                return Ok(());
            }
            for value in object.values() {
                validate_generated_fixture_matchers(value, false)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_fixture_input_value(
    name: &str,
    declaration: &InputDeclaration,
    value: &Value,
) -> Result<()> {
    if declaration
        .enum_values
        .as_ref()
        .is_some_and(|values| !values.contains(value))
        || declaration
            .const_value
            .as_ref()
            .is_some_and(|constant| constant != value)
    {
        bail!("fixture input {name} violates its enum/const contract");
    }
    if value.is_null() {
        if declaration.role == AuthoredInputRole::Parameter && declaration.nullable {
            return Ok(());
        }
        bail!("fixture input {name} cannot be null");
    }
    match declaration.input_type {
        InputType::String | InputType::FullDate => {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow!("fixture input {name} must be a String"))?;
            if value.len() > usize::from(declaration.bytes)
                || declaration
                    .max_length
                    .is_some_and(|maximum| value.chars().count() > usize::from(maximum))
                || declaration
                    .min_length
                    .is_some_and(|minimum| value.chars().count() < usize::from(minimum))
            {
                bail!("fixture input {name} violates its String bounds");
            }
            let canonical = match declaration.canonicalization {
                Canonicalization::Identity => std::borrow::Cow::Borrowed(value),
                Canonicalization::AsciiLowercase => {
                    std::borrow::Cow::Owned(value.to_ascii_lowercase())
                }
            };
            if declaration.pattern.as_ref().is_some_and(|pattern| {
                regex::Regex::new(pattern).map_or(true, |compiled| !compiled.is_match(&canonical))
            }) {
                bail!("fixture input {name} violates its pattern");
            }
            if declaration.input_type == InputType::FullDate
                && time::Date::parse(
                    &canonical,
                    &time::macros::format_description!("[year]-[month]-[day]"),
                )
                .is_err()
            {
                bail!("fixture full-date input {name} is not canonical");
            }
        }
        InputType::Boolean if !value.is_boolean() => {
            bail!("fixture input {name} must be a Boolean");
        }
        InputType::Boolean => {}
        InputType::Integer => {
            let value = value
                .as_i64()
                .ok_or_else(|| anyhow!("fixture input {name} must be an exact Integer"))?;
            if !matches!((declaration.minimum, declaration.maximum), (Some(minimum), Some(maximum)) if (minimum..=maximum).contains(&value))
            {
                bail!("fixture input {name} violates its Integer range");
            }
        }
    }
    Ok(())
}

fn snapshot_output_field(output: &OutputDeclaration) -> Option<&str> {
    let (_, path) = output.from.as_deref()?.split_once('.')?;
    let field = path.strip_prefix("record.").unwrap_or(path);
    (field != "presence").then_some(field)
}

fn validate_integration(alias: &str, integration: &IntegrationDocument) -> Result<()> {
    if integration.version != 1 {
        bail!("integration {alias} version must be 1");
    }
    validate_stable_id(&integration.id, "integration id")?;
    if let Some(product) = &integration.source.product {
        validate_stable_id(product, "source.product")?;
    }
    let versions = integration
        .source
        .versions
        .tested
        .iter()
        .chain(&integration.source.versions.unverified);
    let mut unique_versions = BTreeSet::new();
    for version in versions {
        validate_token(version, "source version", 256)?;
        if !unique_versions.insert(version) {
            bail!("source version evidence classes contain a duplicate");
        }
    }
    if unique_versions.len() > 32 {
        bail!("source versions must contain at most 32 unique entries");
    }
    if integration.source.product.is_some() && unique_versions.is_empty() {
        bail!("source.versions must classify at least one product version label");
    }
    if !(1..=16).contains(&integration.input.len()) {
        bail!("integration {alias} must declare between one and sixteen typed inputs");
    }
    let selector_count = integration
        .input
        .values()
        .filter(|input| input.role == AuthoredInputRole::Selector)
        .count();
    if !(1..=8).contains(&selector_count) {
        bail!("integration {alias} must declare between one and eight selector inputs");
    }
    let selector_bytes = integration
        .input
        .values()
        .filter(|input| input.role == AuthoredInputRole::Selector)
        .try_fold(0_u32, |total, input| {
            total.checked_add(u32::from(input.bytes))
        })
        .ok_or_else(|| anyhow!("canonical selector input bound overflow"))?;
    if selector_bytes > 4096 {
        bail!("canonical selector inputs exceed the fixed 4096-byte aggregate ceiling");
    }
    for (name, input) in &integration.input {
        validate_input_name(name).with_context(|| format!("input.{name}.name"))?;
        if input.bytes == 0 || input.bytes > 4096 {
            bail!("input.{name} worst-case canonical value must be between 1 and 4096 bytes");
        }
        if input
            .pattern
            .as_ref()
            .is_some_and(|pattern| pattern.is_empty() || pattern.len() > 16_384)
        {
            bail!("input.{name}.pattern must be between 1 and 1024 bytes when present");
        }
        if input.input_type == InputType::FullDate
            && (input.bytes != 10
                || input.max_length != Some(10)
                || input.pattern.is_some()
                || !matches!(input.canonicalization, Canonicalization::Identity))
        {
            bail!("full_date input requires the exact RFC 3339 full-date contract");
        }
        if input.role == AuthoredInputRole::Selector && input.nullable {
            bail!("selector inputs cannot be nullable");
        }
    }
    validate_credential_interface(integration)?;
    if integration.outputs.is_empty() || integration.outputs.len() > MAX_OUTPUTS {
        bail!("integration outputs must contain between one and {MAX_OUTPUTS} entries");
    }
    let operations = integration_operations(integration);
    let http = matches!(integration.capability, CapabilityDeclaration::Http { .. });
    let snapshot = matches!(
        integration.capability,
        CapabilityDeclaration::Snapshot { .. }
    );
    if (http && operations.is_empty()) || operations.len() > MAX_OPERATIONS + 2 {
        bail!("compiled source plan exceeds the v1 operation bound");
    }
    if (!snapshot && !(1..=16).contains(&integration.bounds.calls))
        || integration.bounds.source_bytes == 0
        || integration.bounds.source_bytes > 16 * 1024 * 1024
        || integration.bounds.request_bytes == 0
        || integration.bounds.request_bytes > 1024 * 1024
        || integration.bounds.concurrency == 0
        || integration.bounds.concurrency > 64
    {
        bail!("integration bounds are inconsistent with its compiled source plan");
    }
    parse_integration_deadline_ms(&integration.bounds.deadline)?;
    let ordered = ordered_operations(operations)?;
    let mut prior = BTreeSet::new();
    for (operation_id, operation) in ordered {
        validate_stable_id(operation_id, "operation id")?;
        validate_operation(operation, &integration.input, &prior)?;
        prior.insert(operation_id.as_str());
    }
    for (output, declaration) in &integration.outputs {
        validate_stable_id(output, "output id")?;
        if snapshot {
            validate_snapshot_output(output, declaration)?;
        } else {
            validate_output(declaration, operations)?;
        }
    }
    validate_relative_authored_path(&integration.fixtures)?;
    Ok(())
}

fn validate_environment(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
    environment: &EnvironmentDocument,
) -> Result<()> {
    let (requires_relay, requires_notary) = project_product_topology(project);
    let requires_issuance = project_issues_credentials(project);
    let requires_notary_relay = project_requires_notary_relay(project);
    if environment.deployment.relay.is_some() != requires_relay
        || environment.relay.is_some() != requires_relay
    {
        bail!("environment Relay bindings must exactly match the project topology");
    }
    if environment.deployment.notary.is_some() != requires_notary {
        bail!("environment Notary bindings must exactly match the project topology");
    }
    if environment.issuance.is_some() != requires_issuance {
        bail!("environment issuance binding is required exactly when credential profiles exist");
    }
    if environment.notary_relay.is_some() != requires_notary_relay {
        bail!("the Notary-to-Relay connection is required exactly for Relay consultations");
    }
    let remote_integrations = integrations
        .values()
        .filter(|loaded| {
            matches!(
                loaded.document.capability,
                CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. }
            )
        })
        .count();
    if environment.version != 1 || environment.integrations.len() != remote_integrations {
        bail!("environment must bind every remote-source integration exactly once");
    }
    for (alias, loaded) in integrations {
        match &loaded.document.capability {
            CapabilityDeclaration::Snapshot { .. } => {
                if environment.integrations.contains_key(alias) {
                    bail!("snapshot uses only its entity binding and has no integration binding");
                }
            }
            CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
                let binding = environment.integrations.get(alias).ok_or_else(|| {
                    anyhow!("environment is missing remote integration binding {alias}")
                })?;
                validate_source_binding(alias, &loaded.document, &binding.source)?;
            }
        }
    }
    if environment
        .integrations
        .values()
        .map(|binding| binding.source.origin.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
    {
        bail!("all project integrations must bind the same logical source data origin");
    }
    if environment
        .integrations
        .keys()
        .any(|key| !integrations.contains_key(key))
    {
        bail!("environment contains an unknown integration binding");
    }
    if environment.entities.len() != entities.len() {
        bail!("environment must bind every project entity exactly once");
    }
    for (id, loaded) in entities {
        let binding = environment
            .entities
            .get(id)
            .ok_or_else(|| anyhow!("environment is missing project entity {id}"))?;
        validate_environment_entity(&loaded.document, binding)?;
    }
    if environment
        .entities
        .keys()
        .any(|entity| !entities.contains_key(entity))
    {
        bail!("environment contains an unknown project entity");
    }
    if requires_notary && environment.callers.is_empty() && environment.oid4vci.is_none() {
        bail!("a Notary environment must bind at least one authenticated caller");
    }
    if !requires_notary && !environment.callers.is_empty() {
        bail!("a Relay-only environment cannot declare Notary callers");
    }
    if environment.callers.len() > 64 {
        bail!("environment callers exceed the supported bound");
    }
    for (caller_id, caller) in &environment.callers {
        validate_stable_id(caller_id, "caller id")?;
        validate_secret_reference(&caller.api_key_fingerprint)?;
        validate_scopes(&caller.scopes)?;
    }
    if let Some(issuance) = &environment.issuance {
        validate_secret_reference(&issuance.signing_key)?;
        validate_token(&issuance.issuer, "issuance issuer", 2048)?;
        validate_token(&issuance.signing_kid, "issuance signing_kid", 2048)?;
        if issuance.generation == 0 {
            bail!("issuance generation must be positive");
        }
    }
    if let Some(relay) = &environment.relay {
        let local = matches!(environment.deployment.profile, DeploymentProfile::Local);
        validate_https_or_local_loopback_origin(&relay.origin, "Relay origin", local)?;
        validate_https_or_local_loopback_origin(&relay.issuer, "Relay OIDC issuer", local)?;
        validate_token(&relay.audience, "Relay OIDC audience", 256)?;
        if relay.allowed_clients.len() > 64 {
            bail!("Relay allowed_clients exceeds the supported bound");
        }
        let mut allowed_clients = BTreeSet::new();
        for client in &relay.allowed_clients {
            validate_token(client, "Relay allowed client id", 256)?;
            if !allowed_clients.insert(client) {
                bail!("Relay allowed_clients must not contain duplicates");
            }
        }
        let publishes_records = project
            .services
            .values()
            .any(|service| service.kind == ServiceKind::RecordsApi);
        if publishes_records && relay.allowed_clients.is_empty() {
            bail!("a records_api service requires at least one admitted Relay OIDC client");
        }
        if relay.allowed_clients.is_empty() && environment.notary_relay.is_none() {
            bail!("a Relay environment must admit at least one OIDC client");
        }
        validate_https_or_local_loopback_resource(&relay.jwks_url, "Relay OIDC JWKS URL", local)?;
    }
    if let Some(connection) = &environment.notary_relay {
        validate_internal_https_or_loopback_origin(
            &connection.base_url,
            "Notary-to-Relay base URL",
        )?;
        validate_token(
            &connection.workload_client_id,
            "Notary-to-Relay workload client id",
            256,
        )?;
        validate_absolute_runtime_path(&connection.token_file, "Relay workload token file")?;
    }
    if let Some(state) = &environment.relay_state {
        if !requires_notary_relay {
            bail!("relay_state is valid only when Relay consultations are enabled");
        }
        validate_absolute_runtime_path(
            &state.postgresql.root_certificate_path,
            "Relay PostgreSQL root_certificate_path",
        )?;
    }
    if let Some(state) = &environment.notary_state {
        if !requires_notary {
            bail!("notary_state is valid only when the project deploys a Notary");
        }
        validate_absolute_runtime_path(
            &state.postgresql.root_certificate_path,
            "Notary PostgreSQL root_certificate_path",
        )?;
    }
    if let Some(cel) = &environment.notary_cel {
        if !requires_notary {
            bail!("notary_cel is valid only when the project deploys a Notary");
        }
        if !(32 * 1024 * 1024..=1024 * 1024 * 1024).contains(&cel.worker_memory_bytes) {
            bail!("notary_cel.worker_memory_bytes must be between 33554432 and 1073741824");
        }
    }
    if let Some(oid4vci) = &environment.oid4vci {
        validate_oid4vci_binding(project, environment, oid4vci)?;
    }
    if let Some(relay) = &environment.deployment.relay {
        validate_stable_id(&relay.service, "Relay service id")?;
    }
    if let Some(notary) = &environment.deployment.notary {
        validate_stable_id(&notary.service, "Notary service id")?;
    }
    for loaded in integrations.values() {
        if let CapabilityDeclaration::Script { script } = &loaded.document.capability {
            if script.runtime != ScriptRuntime::RhaiV1
                || !is_script_runtime_released(ReleasedScriptRuntime::RhaiV1)
            {
                bail!("script requires a released project-authoring runtime");
            }
        }
    }
    Ok(())
}

fn validate_oid4vci_binding(
    project: &RegistryProject,
    environment: &EnvironmentDocument,
    binding: &Oid4vciBinding,
) -> Result<()> {
    if environment.notary_state.is_none() {
        bail!("OID4VCI requires a Notary PostgreSQL state binding");
    }
    let local = matches!(environment.deployment.profile, DeploymentProfile::Local);
    validate_https_or_local_loopback_origin(
        &binding.public_base_url,
        "OID4VCI public base URL",
        local,
    )?;
    validate_https_or_local_loopback_origin(
        &binding.authorization_server.issuer,
        "OID4VCI authorization server issuer",
        local,
    )?;
    for (field, value) in [
        (
            "OID4VCI authorization server JWKS URL",
            binding.authorization_server.jwks_url.as_str(),
        ),
        (
            "OID4VCI authorization server userinfo URL",
            binding.authorization_server.userinfo_url.as_str(),
        ),
        (
            "OID4VCI authorization server authorize URL",
            binding.authorization_server.authorize_url.as_str(),
        ),
        (
            "OID4VCI authorization server token URL",
            binding.authorization_server.token_url.as_str(),
        ),
        ("OID4VCI redirect URI", binding.redirect_uri.as_str()),
    ] {
        validate_https_or_local_loopback_resource(value, field, local)?;
    }
    for (field, value) in [
        (
            "OID4VCI authorization server JWKS URL",
            binding.authorization_server.jwks_url.as_str(),
        ),
        (
            "OID4VCI authorization server userinfo URL",
            binding.authorization_server.userinfo_url.as_str(),
        ),
        (
            "OID4VCI authorization server token URL",
            binding.authorization_server.token_url.as_str(),
        ),
    ] {
        validate_resource_origin(value, &binding.authorization_server.issuer, field)?;
    }
    let public_base_url = binding.public_base_url.trim_end_matches('/');
    if binding.redirect_uri != format!("{public_base_url}/oid4vci/offer/callback") {
        bail!("OID4VCI redirect URI must be the public Notary offer callback");
    }

    if binding.allowed_wallet_origins.is_empty() || binding.allowed_wallet_origins.len() > 16 {
        bail!("OID4VCI allowed_wallet_origins must contain between one and 16 exact origins");
    }
    let mut wallet_origins = BTreeSet::new();
    for origin in &binding.allowed_wallet_origins {
        validate_https_origin(origin, "OID4VCI wallet origin")?;
        if !wallet_origins.insert(origin) {
            bail!("OID4VCI allowed_wallet_origins must not contain duplicates");
        }
    }

    validate_stable_id(&binding.credential.service, "OID4VCI credential service")?;
    validate_stable_id(&binding.credential.profile, "OID4VCI credential profile")?;
    let service = project
        .services
        .get(&binding.credential.service)
        .ok_or_else(|| anyhow!("OID4VCI references an unknown project service"))?;
    if service.kind != ServiceKind::Evidence {
        bail!("OID4VCI credential service must be an evidence service");
    }
    if service.access.scopes.len() != 1 {
        bail!("OID4VCI credential service must declare exactly one access scope");
    }
    let credential = service
        .credential_profiles
        .get(&binding.credential.profile)
        .ok_or_else(|| anyhow!("OID4VCI references an unknown credential profile"))?;
    if credential.claims.len() != 1 {
        bail!("OID4VCI v1 credential profiles must select exactly one claim");
    }
    let claim = service
        .claims
        .get(&credential.claims[0])
        .ok_or_else(|| anyhow!("OID4VCI credential profile claim is absent"))?;
    if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
        bail!("OID4VCI credential profiles require registry-backed claim evidence");
    }
    if let Some(representative) = &binding.representative_issuance {
        validate_stable_id(
            &representative.relationship,
            "OID4VCI representative relationship",
        )?;
        validate_stable_id(
            &representative.proof_claim,
            "OID4VCI representative proof claim",
        )?;
        validate_token(
            &representative.target_id_type,
            "OID4VCI representative target id type",
            256,
        )?;
        if representative.max_proof_age_seconds == 0
            || representative.max_proof_age_seconds > 600
        {
            bail!("OID4VCI representative max_proof_age_seconds must be between one and 600");
        }
        let credential_claim = &credential.claims[0];
        if let Some((shared_profile, _)) =
            service
                .credential_profiles
                .iter()
                .find(|(profile_id, profile)| {
                    *profile_id != &binding.credential.profile
                        && profile
                            .claims
                            .iter()
                            .any(|claim_id| claim_id == credential_claim)
                })
        {
            bail!(
                "OID4VCI representative credential claim '{}' must be exclusive to credential profile '{}'; credential profile '{}' also selects it",
                credential_claim,
                binding.credential.profile,
                shared_profile
            );
        }
        let proof = service
            .claims
            .get(&representative.proof_claim)
            .ok_or_else(|| {
                anyhow!(
                    "OID4VCI representative_issuance.proof_claim '{}' is not a claim in credential service '{}'",
                    representative.proof_claim,
                    binding.credential.service
                )
            })?;
        if representative.proof_claim == credential.claims[0] {
            bail!(
                "OID4VCI representative_issuance.proof_claim must differ from the credential claim"
            );
        }
        if inferred_claim_evidence(service, proof)? != ClaimEvidence::RegistryBacked {
            bail!("OID4VCI representative_issuance.proof_claim must be registry-backed");
        }
        let consultation_name = claim_consultation_name(service, proof)?;
        let consultation = &service.consultations[consultation_name];
        let requester_mapping = format!(
            "request.requester.identifiers.{}",
            binding.subject.id_type
        );
        let target_mapping = format!(
            "request.target.identifiers.{}",
            representative.target_id_type
        );
        if !consultation
            .input
            .values()
            .any(|mapping| mapping == &requester_mapping)
        {
            bail!(
                "OID4VCI representative_issuance.proof_claim '{}' consultation '{}' must bind the authenticated representative with input mapping '{}'",
                representative.proof_claim,
                consultation_name,
                requester_mapping
            );
        }
        if !consultation
            .input
            .values()
            .any(|mapping| mapping == &target_mapping)
        {
            bail!(
                "OID4VCI representative_issuance.proof_claim '{}' consultation '{}' must bind the represented subject with input mapping '{}'",
                representative.proof_claim,
                consultation_name,
                target_mapping
            );
        }
        if consultation.input.len() != 2
            || consultation
                .input
                .values()
                .any(|mapping| mapping != &requester_mapping && mapping != &target_mapping)
        {
            bail!(
                "OID4VCI representative_issuance.proof_claim '{}' consultation '{}' must map exactly the authenticated representative and represented subject identifiers; the target-selection ceremony cannot supply additional inputs",
                representative.proof_claim,
                consultation_name
            );
        }
    }
    if normalize_credential_format(&credential.format) != "application/dc+sd-jwt" {
        bail!("OID4VCI credential profile format must be dc+sd-jwt");
    }
    let validity_seconds = parse_validity_seconds(&credential.validity)?;
    if validity_seconds == 0 || validity_seconds > 600 {
        bail!("OID4VCI credential validity must be between one and 600 seconds");
    }
    validate_https_or_local_loopback_resource(
        &credential.credential_type,
        "OID4VCI credential type",
        local,
    )?;
    validate_resource_origin(
        &credential.credential_type,
        &binding.public_base_url,
        "OID4VCI credential type",
    )?;
    let credential_path = url::Url::parse(&credential.credential_type)
        .context("OID4VCI credential type is invalid")?
        .path()
        .to_string();
    if !credential_path.starts_with("/credentials/") {
        bail!("OID4VCI credential type path must start with /credentials/");
    }

    validate_token(&binding.client.id, "OID4VCI client id", 256)?;
    if binding.registrar_clients.len() > 64 {
        bail!("OID4VCI registrar_clients exceeds the supported bound");
    }
    let mut registrar_clients = BTreeSet::new();
    for client in &binding.registrar_clients {
        validate_token(client, "OID4VCI registrar client id", 256)?;
        if client == &binding.client.id {
            bail!("OID4VCI registrar_clients must not contain the citizen client id");
        }
        if !registrar_clients.insert(client) {
            bail!("OID4VCI registrar_clients must not contain duplicates");
        }
    }
    validate_secret_reference(&binding.client.signing_key)?;
    validate_token(
        &binding.client.signing_kid,
        "OID4VCI client signing_kid",
        2048,
    )?;
    validate_secret_reference(&binding.access_token.signing_key)?;
    validate_token(
        &binding.access_token.signing_kid,
        "OID4VCI access-token signing_kid",
        2048,
    )?;
    validate_secret_reference(&binding.sensitive_state_key)?;
    validate_token(
        &binding.subject.token_claim,
        "OID4VCI subject token claim",
        256,
    )?;
    validate_token(&binding.subject.id_type, "OID4VCI subject id type", 256)?;

    let issuance = environment
        .issuance
        .as_ref()
        .ok_or_else(|| anyhow!("OID4VCI requires an issuance binding"))?;
    let secret_names = [
        issuance.signing_key.secret.as_str(),
        binding.client.signing_key.secret.as_str(),
        binding.access_token.signing_key.secret.as_str(),
    ];
    if secret_names.into_iter().collect::<BTreeSet<_>>().len() != secret_names.len() {
        bail!("OID4VCI issuer, client, and access-token signing keys must be distinct");
    }
    let signing_kids = [
        issuance.signing_kid.as_str(),
        binding.client.signing_kid.as_str(),
        binding.access_token.signing_kid.as_str(),
    ];
    if signing_kids.into_iter().collect::<BTreeSet<_>>().len() != signing_kids.len() {
        bail!("OID4VCI issuer, client, and access-token signing kids must be distinct");
    }
    Ok(())
}

fn validate_resource_origin(resource: &str, origin: &str, field: &str) -> Result<()> {
    let resource = url::Url::parse(resource).with_context(|| format!("{field} is invalid"))?;
    let origin = url::Url::parse(origin).with_context(|| format!("{field} origin is invalid"))?;
    if resource.scheme() != origin.scheme()
        || resource.host() != origin.host()
        || resource.port_or_known_default() != origin.port_or_known_default()
    {
        bail!("{field} must use its bound origin");
    }
    Ok(())
}

fn project_product_topology(project: &RegistryProject) -> (bool, bool) {
    let requires_notary = project
        .services
        .values()
        .any(|service| service.kind == ServiceKind::Evidence);
    let requires_relay = !project.integrations.is_empty()
        || !project.entities.is_empty()
        || project.services.values().any(|service| {
            service.kind == ServiceKind::RecordsApi || !service.consultations.is_empty()
        });
    (requires_relay, requires_notary)
}

fn project_issues_credentials(project: &RegistryProject) -> bool {
    project
        .services
        .values()
        .any(|service| !service.credential_profiles.is_empty())
}

fn project_requires_notary_relay(project: &RegistryProject) -> bool {
    project
        .services
        .values()
        .any(|service| service.kind == ServiceKind::Evidence && !service.consultations.is_empty())
}

fn is_script_runtime_released(capability: ReleasedScriptRuntime) -> bool {
    is_script_runtime_released_in(capability, RELEASED_SCRIPT_RUNTIMES)
}

fn is_script_runtime_released_in(
    capability: ReleasedScriptRuntime,
    released: &[ReleasedScriptRuntime],
) -> bool {
    released.contains(&capability)
}

fn validate_credential_interface(integration: &IntegrationDocument) -> Result<()> {
    let interface = credential_interface(integration);
    match interface.credential_type {
        CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
            if interface.request.is_some()
                || interface.response_profile.is_some()
                || interface.scope.is_some()
                || interface.audience.is_some()
                || interface.refresh_skew.is_some()
            {
                bail!("API-key credential interfaces cannot declare OAuth fields");
            }
            let name = interface
                .name
                .as_deref()
                .ok_or_else(|| anyhow!("API-key credential interface requires a fixed name"))?;
            let max_value_bytes = interface
                .max_value_bytes
                .filter(|bound| *bound > 0 && *bound <= 4096)
                .ok_or_else(|| anyhow!("API-key credential interface requires a bounded value"))?;
            let _ = max_value_bytes;
            let mut bytes = name.bytes();
            match interface.credential_type {
                CredentialType::ApiKeyHeader => {
                    if name.len() > 64
                        || !matches!(bytes.next(), Some(b'a'..=b'z'))
                        || !bytes
                            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
                    {
                        bail!("API-key header name must be one fixed lower-case HTTP token");
                    }
                    if is_forbidden_api_key_header(name) {
                        bail!("API-key header name is security-sensitive or hop-by-hop");
                    }
                }
                CredentialType::ApiKeyQuery => {
                    if name.len() > 96
                        || !matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
                        || !bytes.all(|byte| {
                            matches!(
                                byte,
                                b'a'..=b'z'
                                    | b'A'..=b'Z'
                                    | b'0'..=b'9'
                                    | b'.'
                                    | b'_'
                                    | b':'
                                    | b'~'
                                    | b'-'
                            )
                        })
                    {
                        bail!("API-key query name is outside the closed reviewed grammar");
                    }
                    if integration_operations(integration)
                        .values()
                        .any(|operation| operation.request.query.contains_key(name))
                    {
                        bail!("API-key query name collides with an authored request parameter");
                    }
                }
                _ => unreachable!(),
            }
        }
        CredentialType::Oauth2ClientCredentials => {
            if interface.name.is_some() || interface.max_value_bytes.is_some() {
                bail!("non-API-key credential interfaces cannot declare API-key fields");
            }
            if interface.request.is_none()
                || interface.response_profile != Some(OAuthResponseProfile::Oauth2Bearer)
            {
                bail!("OAuth client credentials require request and response_profile");
            }
            if let Some(scope) = &interface.scope {
                let scopes = scope.split_ascii_whitespace().collect::<Vec<_>>();
                if scopes.is_empty()
                    || scopes.len() > 32
                    || scopes.iter().any(|scope| {
                        scope.is_empty()
                            || scope.len() > 128
                            || scope.bytes().any(|byte| byte.is_ascii_control())
                    })
                {
                    bail!("OAuth scope is outside the bounded token grammar");
                }
            }
            if let Some(audience) = &interface.audience {
                validate_token(audience, "OAuth audience", 2048)?;
            }
            if let Some(refresh_skew) = interface.refresh_skew.as_deref() {
                parse_oauth_refresh_skew_ms(refresh_skew)?;
            }
        }
        CredentialType::None | CredentialType::Basic | CredentialType::StaticBearer => {
            if interface.name.is_some()
                || interface.max_value_bytes.is_some()
                || interface.request.is_some()
                || interface.response_profile.is_some()
                || interface.scope.is_some()
                || interface.audience.is_some()
                || interface.refresh_skew.is_some()
            {
                bail!("non-OAuth credential interfaces cannot declare credential extension fields");
            }
        }
    }
    Ok(())
}

fn validate_source_binding(
    alias: &str,
    integration: &IntegrationDocument,
    source: &EnvironmentSourceBinding,
) -> Result<()> {
    validate_https_origin(
        &source.origin,
        &format!("integrations.{alias}.source.origin"),
    )?;
    validate_private_cidrs(
        &source.allowed_private_cidrs,
        &format!("integrations.{alias}.source.allowed_private_cidrs"),
    )?;
    validate_transport_identity(
        source.ca.as_ref(),
        source.mtls.as_ref(),
        &format!("integrations.{alias}.source"),
    )?;
    if source
        .concurrency
        .is_some_and(|value| value == 0 || value > 64)
    {
        bail!("integrations.{alias}.source.concurrency must be between 1 and 64");
    }
    if let Some(timeout) = source.timeout.as_deref() {
        parse_environment_source_timeout_ms(timeout)?;
    }
    if let Some(rate) = &source.rate {
        if rate.per_minute == 0
            || rate.per_minute > 60_000
            || rate.burst == 0
            || u32::from(rate.burst) > rate.per_minute
        {
            bail!("integrations.{alias}.source.rate is outside the deployment bounds");
        }
    }
    validate_source_credential_binding(alias, credential_interface(integration), source)?;
    match (has_authored_signed_dci(integration), source.jwks.as_ref()) {
        (true, Some(jwks)) => {
            validate_private_endpoint(jwks, &format!("integrations.{alias}.source.jwks"))?;
        }
        (true, None) => bail!("signed DCI requires one exact private JWKS binding"),
        (false, Some(_)) => bail!("source.jwks is valid only for a signed-DCI integration"),
        (false, None) => {}
    }
    Ok(())
}

fn validate_source_credential_binding(
    alias: &str,
    interface: &CredentialInterface,
    source: &EnvironmentSourceBinding,
) -> Result<()> {
    let credential = source.credential.as_ref();
    let exact = match interface.credential_type {
        CredentialType::None => credential.is_none() && source.oauth.is_none(),
        CredentialType::Basic => {
            credential.is_some_and(|credential| {
                credential.generation > 0
                    && credential.username.is_some()
                    && credential.password.is_some()
                    && credential.token.is_none()
                    && credential.client_id.is_none()
                    && credential.client_secret.is_none()
                    && credential.value.is_none()
            }) && source.oauth.is_none()
        }
        CredentialType::StaticBearer => {
            credential.is_some_and(|credential| {
                credential.generation > 0
                    && credential.username.is_none()
                    && credential.password.is_none()
                    && credential.token.is_some()
                    && credential.client_id.is_none()
                    && credential.client_secret.is_none()
                    && credential.value.is_none()
            }) && source.oauth.is_none()
        }
        CredentialType::Oauth2ClientCredentials => {
            credential.is_some_and(|credential| {
                credential.generation > 0
                    && credential.username.is_none()
                    && credential.password.is_none()
                    && credential.token.is_none()
                    && credential.client_id.is_some()
                    && credential.client_secret.is_some()
                    && credential.value.is_none()
            }) && source.oauth.is_some()
        }
        CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
            credential.is_some_and(|credential| {
                credential.generation > 0
                    && credential.username.is_none()
                    && credential.password.is_none()
                    && credential.token.is_none()
                    && credential.client_id.is_none()
                    && credential.client_secret.is_none()
                    && credential.value.is_some()
            }) && source.oauth.is_none()
        }
    };
    if !exact {
        bail!("integrations.{alias}.source.credential does not match source.auth.type");
    }
    if let Some(credential) = credential {
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
    }
    if let Some(oauth) = &source.oauth {
        validate_private_endpoint(oauth, &format!("integrations.{alias}.source.oauth"))?;
    }
    Ok(())
}

fn validate_private_endpoint(endpoint: &PrivateEndpointBinding, field: &str) -> Result<()> {
    validate_https_origin(&endpoint.origin, &format!("{field}.origin"))?;
    validate_exact_private_path(&endpoint.path, &format!("{field}.path"))?;
    validate_private_cidrs(
        &endpoint.allowed_private_cidrs,
        &format!("{field}.allowed_private_cidrs"),
    )?;
    validate_transport_identity(endpoint.ca.as_ref(), endpoint.mtls.as_ref(), field)?;
    if endpoint.generation == 0 {
        bail!("{field}.generation must be positive");
    }
    Ok(())
}

fn validate_transport_identity(
    ca: Option<&CertificateAuthorityBinding>,
    mtls: Option<&MutualTlsBinding>,
    field: &str,
) -> Result<()> {
    if let Some(ca) = ca {
        validate_absolute_runtime_path(&ca.file, &format!("{field}.ca.file"))?;
        if ca.generation == 0 {
            bail!("{field}.ca.generation must be positive");
        }
    }
    if let Some(mtls) = mtls {
        validate_absolute_runtime_path(
            &mtls.certificate_file,
            &format!("{field}.mtls.certificate_file"),
        )?;
        validate_secret_reference(&mtls.private_key)?;
        if mtls.generation == 0 {
            bail!("{field}.mtls.generation must be positive");
        }
    }
    Ok(())
}

fn validate_private_cidrs(cidrs: &[String], field: &str) -> Result<()> {
    if cidrs.len() > 16 {
        bail!("{field} contains more than sixteen CIDRs");
    }
    let mut canonical = BTreeSet::new();
    for cidr in cidrs {
        let parsed = cidr
            .parse::<ipnet::IpNet>()
            .with_context(|| format!("{field} contains an invalid CIDR"))?;
        if parsed.trunc().to_string() != *cidr || !canonical.insert(cidr) {
            bail!("{field} must contain unique canonical CIDRs");
        }
    }
    Ok(())
}

fn validate_exact_private_path(path: &str, field: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || !path.starts_with('/')
        || path == "/"
        || path.contains(['?', '#', '\\'])
        || path.split('/').skip(1).any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || segment.to_ascii_lowercase().contains("%2f")
                || segment.to_ascii_lowercase().contains("%5c")
        })
    {
        bail!("{field} must be one exact canonical non-root path");
    }
    Ok(())
}

fn has_authored_signed_dci(integration: &IntegrationDocument) -> bool {
    match &integration.capability {
        CapabilityDeclaration::Http { http } => http
            .operations
            .values()
            .any(|operation| operation.primitive.as_deref() == Some("dci_search_v1")),
        CapabilityDeclaration::Script { script } => script.signed_dci.is_some(),
        CapabilityDeclaration::Snapshot { .. } => false,
    }
}

fn is_forbidden_api_key_header(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "cookie"
            | "host"
            | "connection"
            | "content-length"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
    )
}

fn validate_environment_entity(
    entity: &EntityDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<()> {
    let expected = entity
        .schema
        .properties
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if binding
        .columns
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
    {
        bail!("environment entity columns must bind every logical field exactly once");
    }
    let mut physical = BTreeSet::new();
    for column in binding.columns.values() {
        validate_stable_id(column, "records physical column")?;
        if !physical.insert(column) {
            bail!("environment entity physical column mapping must be injective");
        }
    }
    validate_token(&binding.source_revision, "entity source revision", 256)?;
    validate_token(&binding.generation, "entity generation", 256)?;
    let path = match &binding.provider {
        RecordProvider::Csv { path, .. }
        | RecordProvider::Xlsx { path, .. }
        | RecordProvider::Parquet { path } => Some(path),
        RecordProvider::Postgres {
            connection,
            schema,
            table,
        } => {
            validate_secret_reference(connection)?;
            if !is_lower_snake_id(schema) || !is_lower_snake_id(table) {
                bail!("PostgreSQL schema and table must use lower-snake identifiers");
            }
            None
        }
    };
    if let Some(path) = path {
        validate_absolute_runtime_path(path, "entity provider path")?;
    }
    if let RecordProvider::Xlsx { sheet, .. } = &binding.provider {
        validate_token(sheet, "entity provider sheet", 256)?;
    }
    if let RecordProvider::Xlsx { project_file, .. } = &binding.provider {
        validate_relative_authored_path(project_file)
            .context("entity provider project_file is invalid")?;
    }
    Ok(())
}

fn validate_environment_project_files(
    root: &Path,
    environment: &EnvironmentDocument,
) -> Result<()> {
    for binding in environment.entities.values() {
        if let RecordProvider::Xlsx { project_file, .. } = &binding.provider {
            reject_symlink_components(root, &root.join(project_file))
                .context("entity provider project_file is invalid")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod fixture_matcher_validation_tests {
    use super::*;

    #[test]
    fn generated_matchers_are_confined_to_supported_request_body_leaves() {
        for valid in [
            serde_json::json!({"correlation": {"generated": "dci-correlation"}}),
            serde_json::json!({"timestamp": {"generated": "rfc3339-timestamp"}}),
        ] {
            validate_generated_fixture_matchers(&valid, false).expect("supported matcher");
        }
        for invalid in [
            serde_json::json!({"generated": "arbitrary"}),
            serde_json::json!({"generated": "dci-correlation", "prefix": "chosen"}),
            serde_json::json!({"generated": {"generated": "dci-correlation"}}),
        ] {
            assert!(validate_generated_fixture_matchers(&invalid, false).is_err());
        }
    }
}
