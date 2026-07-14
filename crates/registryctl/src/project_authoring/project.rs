// SPDX-License-Identifier: Apache-2.0

fn load_registry_project(root: &Path, environment: Option<&str>) -> Result<LoadedRegistryProject> {
    let root = canonical_root(root)?;
    let project_path = root.join(PROJECT_FILE);
    let project_bytes = read_authored_file(&root, &project_path)?;
    let project: RegistryProject = parse_yaml(&project_bytes, PROJECT_FILE)?;
    validate_project_shape(&project)?;

    let mut hasher = Sha256::new();
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
        hash_authored_file(
            &mut hasher,
            relative
                .to_str()
                .ok_or_else(|| anyhow!("entity definition path is not Unicode"))?,
            &bytes,
        );
        let document: EntityDefinition = parse_yaml(&bytes, &relative.display().to_string())?;
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
        hash_authored_file(
            &mut hasher,
            reference
                .file
                .to_str()
                .ok_or_else(|| anyhow!("integration path is not Unicode"))?,
            &bytes,
        );
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
        let fixtures = load_fixtures(&root, &fixture_dir, &mut hasher)?;
        validate_fixture_inputs(alias, &document, &fixtures)?;
        let script = integration_script(&document)
            .map(|script| {
                let script_path = resolve_relative_to_file(&root, &path, script)?;
                let script_bytes = read_authored_file(&root, &script_path)?;
                let relative = script_path
                    .strip_prefix(&root)
                    .map_err(|_| anyhow!("script path escapes project root"))?;
                hash_authored_file(
                    &mut hasher,
                    relative
                        .to_str()
                        .ok_or_else(|| anyhow!("script path is not Unicode"))?,
                    &script_bytes,
                );
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
                hash_authored_file(
                    &mut hasher,
                    relative
                        .to_str()
                        .ok_or_else(|| anyhow!("script module path is not Unicode"))?,
                    &module_bytes,
                );
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
            hash_authored_file(
                &mut hasher,
                relative
                    .to_str()
                    .ok_or_else(|| anyhow!("environment path is not Unicode"))?,
                &bytes,
            );
            let document: EnvironmentDocument =
                parse_yaml(&bytes, &relative.display().to_string())?;
            validate_environment(&project, &integrations, &entities, &document)?;
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
        project_content_digest,
        semantic_digests,
    })
}

fn project_content_digest(root: &Path, authored_hasher: &Sha256) -> Result<String> {
    const MAX_ENVIRONMENTS: usize = 64;

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
    let AuthoredCapabilityDeclaration::Snapshot { snapshot } = &authored.capability else {
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
    parse_duration_ms_with_max(
        &snapshot.freshness,
        31 * 24 * 60 * 60 * 1_000,
        "snapshot freshness",
    )?;
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
                    max_source_bytes: entity
                        .materialization
                        .max_bytes
                        .bytes("entity.materialization.max_bytes")?,
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
            subject_mismatch: authored.not_applicable.subject_mismatch.as_ref().map(|reason| {
                NotApplicableReason {
                    rationale: reason.rationale.clone(),
                    request_fixture: reason.request_fixture.clone(),
                }
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
            let entity = entities
                .get(&snapshot.entity)
                .ok_or_else(|| anyhow!("snapshot ambiguity evidence references an unknown entity"))?;
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
    let evidence =
        validate_not_applicable_evidence(alias, "subject_mismatch", reason, fixtures)?;
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
    if evidence.interactions.iter().any(|interaction| match &interaction.respond {
        FixtureSourceResponse::Http { body, .. } => selector_values
            .iter()
            .any(|selector| json_contains_scalar(body, selector)),
        FixtureSourceResponse::Timeout { .. } => false,
    }) {
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
        json!({
            "integrations": integrations,
            "entities": environment.entities,
            "caller_credentials": caller_credentials,
            "issuance": environment.issuance,
            "relay": environment.relay,
            "notary_relay": environment.notary_relay,
            "notary_state": environment.notary_state,
            "deployment": environment.deployment,
        })
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
    for (service_id, service) in &project.services {
        validate_stable_id(service_id, "service id")?;
        match service.kind {
            ServiceKind::RecordsApi => {
                if service.version != 0
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
                        bail!("self-attested claims cannot reference Relay outputs");
                    }
                    if claim.value.is_none() {
                        bail!("self-attested claims require an explicit value contract");
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
                        bail!("self-attested claims cannot depend on Relay consultations");
                    }
                }
            }
            if let Some(value) = &claim.value {
                if value.value_type == OutputType::String && value.max_bytes.is_none() {
                    bail!("string claim value contracts require max_bytes");
                }
                if value.value_type != OutputType::String && value.max_bytes.is_some() {
                    bail!("only string claim value contracts may declare max_bytes");
                }
            }
            validate_disclosure(&claim.disclosure)?;
        }
        for credential in service.credential_profiles.values() {
            if credential.claims.is_empty() {
                bail!("credential claim allow-list must not be empty");
            }
            for claim in &credential.claims {
                if !service.claims.contains_key(claim) {
                    bail!("credential references an unknown claim");
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
    if entity.materialization.max_records == 0
        || entity.materialization.max_records > 100_000_000
        || entity
            .materialization
            .max_bytes
            .bytes("entity.materialization.max_bytes")?
            > 1024 * 1024 * 1024
        || !(1..=16).contains(&entity.materialization.retain_generations)
    {
        bail!("entity materialization exceeds the v1 bounds");
    }
    if entity.materialization.refresh != "manual" {
        parse_duration_ms(&entity.materialization.refresh)
            .context("entity materialization refresh is invalid")?;
    }
    Ok(())
}

fn validate_records_service(service: &ServiceDeclaration, entity: &EntityDefinition) -> Result<()> {
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
    validate_scopes(&[api.scopes.metadata.clone(), api.scopes.rows.clone()])?;
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
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::RecordsApi)
    {
        let entity_id = service
            .entity
            .as_deref()
            .ok_or_else(|| anyhow!("records_api service entity is absent"))?;
        let entity = &entities
            .get(entity_id)
            .ok_or_else(|| anyhow!("records_api service references an unknown entity"))?
            .document;
        validate_records_service(service, entity)?;
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
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::Evidence)
    {
        for consultation in service.consultations.values() {
            let integration = &integrations[&consultation.integration].document;
            if consultation.input.keys().ne(integration.input.keys()) {
                bail!("consultation input must bind the integration input set exactly");
            }
            if consultation.input.values().collect::<BTreeSet<_>>().len()
                != consultation.input.len()
            {
                bail!("consultation target mappings must be injective");
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
                    if parse_duration_ms(timeout)? == 0 {
                        bail!("fixture timeout must be positive");
                    }
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
        bail!("integration outputs must contain between one and 64 entries");
    }
    let operations = integration_operations(integration);
    let http = matches!(integration.capability, CapabilityDeclaration::Http { .. });
    let snapshot = matches!(integration.capability, CapabilityDeclaration::Snapshot { .. });
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
    parse_duration_ms(&integration.bounds.deadline)?;
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
    if requires_notary && environment.callers.is_empty() {
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
        validate_https_or_local_loopback_resource(
            &relay.jwks_url,
            "Relay OIDC JWKS URL",
            local,
        )?;
    }
    if let Some(connection) = &environment.notary_relay {
        validate_token(
            &connection.workload_client_id,
            "Notary-to-Relay workload client id",
            256,
        )?;
        validate_absolute_runtime_path(&connection.token_file, "Relay workload token file")?;
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
    project.services.values().any(|service| {
        service.kind == ServiceKind::Evidence && !service.consultations.is_empty()
    })
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
            if interface
                .refresh_skew
                .as_deref()
                .map(parse_duration_ms)
                .transpose()?
                .is_some_and(|skew| skew == 0 || skew >= 3_600_000)
            {
                bail!("OAuth refresh_skew must be positive and below one hour");
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
    if source
        .timeout
        .as_deref()
        .map(parse_duration_ms)
        .transpose()?
        .is_some_and(|value| value == 0 || value > 60_000)
    {
        bail!("integrations.{alias}.source.timeout must be between 1ms and 60s");
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
