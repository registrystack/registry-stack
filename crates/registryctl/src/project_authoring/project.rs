// SPDX-License-Identifier: Apache-2.0

fn load_registry_project(root: &Path, environment: Option<&str>) -> Result<LoadedRegistryProject> {
    let root = canonical_root(root)?;
    let project_path = root.join(PROJECT_FILE);
    let project_bytes = read_authored_file(&root, &project_path)?;
    let project: RegistryProject = parse_yaml(&project_bytes, PROJECT_FILE)?;
    validate_project_shape(&project)?;

    let mut hasher = Sha256::new();
    hash_authored_file(&mut hasher, PROJECT_FILE, &project_bytes);
    let mut records = BTreeMap::new();
    for service in project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::RecordsApi)
    {
        let relative = service
            .definition
            .as_ref()
            .ok_or_else(|| anyhow!("records_api definition is absent"))?;
        let path = resolve_authored_path(&root, relative)?;
        let bytes = read_authored_file(&root, &path)?;
        hash_authored_file(
            &mut hasher,
            relative
                .to_str()
                .ok_or_else(|| anyhow!("records definition path is not Unicode"))?,
            &bytes,
        );
        let document: RecordsDefinition = parse_yaml(&bytes, &relative.display().to_string())?;
        validate_records_definition(&document)?;
        if service.entity.as_deref() != Some(document.id.as_str()) {
            bail!("records_api entity must match its records definition id");
        }
        if records
            .insert(document.id.clone(), LoadedRecordsDefinition { document })
            .is_some()
        {
            bail!("one records entity cannot be declared by multiple services");
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
        let document: IntegrationDocument =
            parse_yaml(&bytes, &reference.file.display().to_string())?;
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
        integrations.insert(
            alias.clone(),
            LoadedIntegration {
                document,
                fixtures,
                script,
            },
        );
    }
    validate_service_integration_links(&project, &integrations)?;
    validate_project_records_links(&integrations, &records)?;

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
            validate_environment(&project, &integrations, &records, &document)?;
            (Some(name.to_owned()), Some(document))
        }
        None => (None, None),
    };
    let semantic_digests =
        semantic_digests(&project, &integrations, &records, environment.as_ref())?;
    Ok(LoadedRegistryProject {
        root,
        project,
        environment_name,
        environment,
        integrations,
        records,
        authored_hash: format!("sha256:{}", hex::encode(hasher.finalize())),
        semantic_digests,
    })
}

fn semantic_digests(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    records: &BTreeMap<String, LoadedRecordsDefinition>,
    environment: Option<&EnvironmentDocument>,
) -> Result<SemanticDigests> {
    let claims = project
        .services
        .iter()
        .map(|(id, service)| {
            (
                id,
                json!({
                    "variables": service.variables,
                    "claims": service.claims.iter().map(|(claim_id, claim)| (
                        claim_id,
                        json!({
                            "evidence": claim.evidence,
                            "output": claim.output,
                            "cel": claim.cel,
                            "value": claim.value,
                        }),
                    )).collect::<BTreeMap<_, _>>(),
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
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
                    "credentials": service.credentials,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_policy = records
        .iter()
        .map(|(id, loaded)| {
            (
                id,
                json!({
                    "scopes": loaded.document.api.scopes,
                    "purposes": loaded.document.api.purposes,
                    "required_principal_filters": loaded.document.api.required_principal_filters,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let records_model = records
        .iter()
        .map(|(id, loaded)| {
            let definition = &loaded.document;
            (
                id,
                json!({
                    "version": definition.version,
                    "id": definition.id,
                    "title": definition.title,
                    "description": definition.description,
                    "owner": definition.owner,
                    "sensitivity": definition.sensitivity,
                    "access_rights": definition.access_rights,
                    "update_frequency": definition.update_frequency,
                    "conforms_to": definition.conforms_to,
                    "primary_key": definition.primary_key,
                    "fields": definition.fields,
                    "pagination": definition.api.pagination,
                    "filters": definition.api.filters,
                    "relationships": definition.api.relationships,
                    "aggregates": definition.api.aggregates,
                    "standards": definition.api.standards,
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
            let source_version = environment
                .and_then(|environment| environment.integrations.get(alias))
                .map(|binding| binding.source_version.as_str());
            let snapshot_mapping = match &loaded.document.capability {
                CapabilityDeclaration::Snapshot { snapshot } => environment
                    .and_then(|environment| environment.entities.get(&snapshot.entity))
                    .map(|binding| json!({ "columns": binding.columns })),
                CapabilityDeclaration::Http { .. }
                | CapabilityDeclaration::Script { .. } => None,
            };
            Ok((
                alias,
                json!({
                    "document": loaded.document,
                    "fixtures": fixture_digests,
                    "script_digest": script_digest,
                    "source_version": source_version,
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
                        "data_destination": binding.data_destination,
                        "credential_destination": binding.credential_destination,
                        "credential": binding.credential,
                        "advanced_capabilities": binding.advanced_capabilities,
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
            "deployment": environment.deployment,
        })
    });
    Ok(SemanticDigests {
        claim: digest_json(&json!({ "services": claims }))?,
        integration: digest_json(&json!({
            "integrations": integration,
            "service_consultations": service_consultations,
            "records": records_model,
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
    if project.integrations.len() > 16 {
        bail!("project must declare no more than 16 integrations");
    }
    if project.services.is_empty() || project.services.len() > 32 {
        bail!("project must declare between one and 32 services");
    }
    for (alias, reference) in &project.integrations {
        validate_stable_id(alias, "integration alias")?;
        validate_relative_authored_path(&reference.file)?;
    }
    let mut project_claim_ids = BTreeSet::new();
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
                    || !service.credentials.is_empty()
                {
                    bail!("records_api service may declare only kind, definition, and entity");
                }
                let definition = service
                    .definition
                    .as_ref()
                    .ok_or_else(|| anyhow!("records_api service requires a definition"))?;
                validate_relative_authored_path(definition)?;
                validate_stable_id(
                    service
                        .entity
                        .as_deref()
                        .ok_or_else(|| anyhow!("records_api service requires an entity"))?,
                    "records_api entity",
                )?;
                continue;
            }
            ServiceKind::Evidence => {
                if service.definition.is_some() || service.entity.is_some() {
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
            if !(1..=4).contains(&consultation.input.len()) {
                bail!(
                    "consultation input must contain between one and four typed subject mappings"
                );
            }
            for mapping in consultation.input.values() {
                validate_request_mapping(mapping)?;
            }
        }
        for (variable, declaration) in &service.variables {
            validate_stable_id(variable, "request variable")?;
            if declaration.from != format!("request.variables.{variable}")
                || declaration.value_type != FactType::Date
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
            match claim.evidence {
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
                        claim.cel.as_deref().expect("claim source shape was checked"),
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
                if value.value_type == FactType::String && value.max_bytes.is_none() {
                    bail!("string claim value contracts require max_bytes");
                }
                if value.value_type != FactType::String && value.max_bytes.is_some() {
                    bail!("only string claim value contracts may declare max_bytes");
                }
            }
            validate_disclosure(&claim.disclosure)?;
        }
        for credential in service.credentials.values() {
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

fn validate_records_definition(records: &RecordsDefinition) -> Result<()> {
    if records.version != 1 {
        bail!("records definition version must be 1");
    }
    validate_stable_id(&records.id, "records id")?;
    if records.id.len() > 45 || !is_lower_snake_id(&records.id) {
        bail!("records id exceeds the shared materialization provider bound");
    }
    validate_stable_id(&records.primary_key, "records primary_key")?;
    if records.fields.is_empty() || records.fields.len() > 256 {
        bail!("records fields must contain between one and 256 entries");
    }
    if !records.fields.contains_key(&records.primary_key) {
        bail!("records primary_key must reference a declared logical field");
    }
    for (name, field) in &records.fields {
        validate_stable_id(name, "records field")?;
        if !is_lower_snake_id(name) {
            bail!("records fields must use Relay lower-snake ids");
        }
        if name == &records.primary_key && field.nullable {
            bail!("records primary_key must be non-nullable");
        }
    }
    validate_scopes(&[
        records.api.scopes.metadata.clone(),
        records.api.scopes.rows.clone(),
    ])?;
    for scope in [
        Some(&records.api.scopes.metadata),
        Some(&records.api.scopes.rows),
        records.api.scopes.aggregate.as_ref(),
        records.api.scopes.evidence_verification.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_token(scope, "records scope", 128)?;
        if scope.split_once(':').map(|(dataset, _)| dataset) != Some(records.id.as_str()) {
            bail!("records scopes must use their records id namespace");
        }
    }
    if records.api.pagination.default_limit == 0
        || records.api.pagination.max_limit == 0
        || records.api.pagination.default_limit > records.api.pagination.max_limit
        || records.api.pagination.max_limit > 10_000
    {
        bail!("records pagination limits are invalid");
    }
    for purpose in &records.api.purposes {
        validate_token(purpose, "records purpose", 256)?;
    }
    let field_names = records
        .fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for (field, operators) in &records.api.filters {
        if !field_names.contains(field.as_str()) || operators.is_empty() {
            bail!("records filters must name declared fields and at least one operator");
        }
        if operators.iter().collect::<BTreeSet<_>>().len() != operators.len() {
            bail!("records filter operators must be unique");
        }
    }
    for field in &records.api.required_principal_filters {
        if !field_names.contains(field.as_str()) || !records.api.filters.contains_key(field) {
            bail!("required principal filters must be allow-listed records fields");
        }
    }
    for (name, relationship) in &records.api.relationships {
        validate_stable_id(name, "records relationship")?;
        if !is_lower_snake_id(name) {
            bail!("records relationships must use Relay lower-snake ids");
        }
        validate_stable_id(&relationship.target, "records relationship target")?;
        if !field_names.contains(relationship.foreign_key.as_str()) {
            bail!("records relationship foreign_key must be a declared field");
        }
    }
    for (id, aggregate) in &records.api.aggregates {
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
            .any(|join| !records.api.relationships.contains_key(join))
        {
            bail!("records aggregate joins must name declared relationships");
        }
    }
    validate_record_standards(records, &field_names)?;
    Ok(())
}

fn is_lower_snake_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn validate_record_standards(records: &RecordsDefinition, fields: &BTreeSet<&str>) -> Result<()> {
    match &records.api.standards.ogc_features {
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
            if referenced.into_iter().any(|field| !fields.contains(field)) {
                bail!("OGC spatial configuration must use declared logical fields");
            }
        }
    }
    match &records.api.standards.sp_dci {
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
        }
    }
    Ok(())
}

fn validate_project_records_links(
    integrations: &BTreeMap<String, LoadedIntegration>,
    records: &BTreeMap<String, LoadedRecordsDefinition>,
) -> Result<()> {
    for loaded in integrations.values() {
        let CapabilityDeclaration::Snapshot { snapshot } = &loaded.document.capability
        else {
            continue;
        };
        let definition = records.get(&snapshot.entity).ok_or_else(|| {
            anyhow!("snapshot references an unknown governed records entity")
        })?;
        if loaded
            .document
            .input
            .keys()
            .any(|input| !definition.document.fields.contains_key(input))
        {
            bail!("snapshot inputs must name declared logical records fields");
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
                .any(|field| loaded.document.input.contains_key(*field))
            || projected
                .iter()
                .any(|field| !definition.document.fields.contains_key(*field))
        {
            bail!("snapshot projection must be a non-empty logical records subset distinct from its selector key");
        }
        for name in projected {
            let field = &definition.document.fields[name];
            let output = loaded
                .document
                .outputs
                .get(name)
                .ok_or_else(|| anyhow!("snapshot logical field is absent"))?;
            let compatible = matches!(
                (field.field_type, output.output_type),
                (RecordFieldType::String, FactType::String)
                    | (RecordFieldType::Integer, FactType::Integer)
                    | (RecordFieldType::Boolean, FactType::Boolean)
                    | (RecordFieldType::Date, FactType::Date)
            );
            if !compatible || field.nullable != output.nullable {
                bail!("snapshot outputs must preserve records field type and nullability");
            }
        }
    }
    for definition in records.values() {
        for relationship in definition.document.api.relationships.values() {
            if !records.contains_key(&relationship.target) {
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
    if integrations
        .values()
        .map(|integration| integration.document.source.product.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        > 1
    {
        bail!("all project integrations must describe the same logical source");
    }
    for service in project
        .services
        .values()
        .filter(|service| {
            service.kind == ServiceKind::Evidence
        })
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
    for (_, fixture) in fixtures {
        if fixture.input.keys().ne(integration.input.keys()) {
            bail!(
                "fixture {} must bind every {alias} input exactly once",
                fixture.name
            );
        }
        for (name, declaration) in &integration.input {
            let value = fixture.input[name]
                .as_str()
                .ok_or_else(|| anyhow!("fixture input must be a string"))?;
            if declaration.input_type == InputType::FullDate
                && time::Date::parse(
                    value,
                    &time::macros::format_description!("[year]-[month]-[day]"),
                )
                .is_err()
            {
                bail!("fixture full_date input is not canonical");
            }
        }
    }
    Ok(())
}

fn snapshot_output_field(output: &OutputDeclaration) -> Option<&str> {
    let (_, path) = output.from.split_once('.')?;
    let field = path.strip_prefix("record.").unwrap_or(path);
    (field != "presence").then_some(field)
}

fn validate_integration(alias: &str, integration: &IntegrationDocument) -> Result<()> {
    if integration.version != 1 {
        bail!("integration {alias} version must be 1");
    }
    validate_stable_id(&integration.id, "integration id")?;
    validate_stable_id(&integration.source.product, "source.product")?;
    let versions = integration
        .source
        .versions
        .tested
        .iter()
        .chain(&integration.source.versions.supported)
        .chain(&integration.source.versions.unverified);
    let mut unique_versions = BTreeSet::new();
    for version in versions {
        validate_token(version, "source version", 256)?;
        if !unique_versions.insert(version) {
            bail!("source version evidence classes contain a duplicate");
        }
    }
    if unique_versions.is_empty() || unique_versions.len() > 32 {
        bail!("source versions must contain between one and 32 unique entries");
    }
    if !(1..=4).contains(&integration.input.len()) {
        bail!("integration {alias} must declare between one and four typed subject inputs");
    }
    for (name, input) in &integration.input {
        validate_input_name(name).with_context(|| format!("input.{name}.name"))?;
        if input.bytes == 0 || input.bytes > MAX_BOUNDED_INPUT_BYTES {
            bail!("input.{name}.bytes must be between 1 and {MAX_BOUNDED_INPUT_BYTES}");
        }
        if input.pattern.is_empty() || input.pattern.len() > 1024 {
            bail!("input.{name}.pattern must be between 1 and 1024 bytes");
        }
        if input.input_type == InputType::FullDate
            && (input.bytes != 10
                || input.pattern != "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
                || !matches!(input.canonicalization, Canonicalization::Identity))
        {
            bail!("full_date input requires the exact RFC 3339 full-date contract");
        }
    }
    validate_credential_interface(integration)?;
    if integration.outputs.is_empty() || integration.outputs.len() > MAX_OUTPUTS {
        bail!("integration outputs must contain between one and 64 entries");
    }
    let operations = integration_operations(integration);
    let snapshot = matches!(
        integration.capability,
        CapabilityDeclaration::Snapshot { .. }
    );
    if (!snapshot && operations.is_empty()) || operations.len() > MAX_OPERATIONS {
        bail!("bounded integration must contain between one and five operations");
    }
    if usize::from(integration.bounds.calls) != operations.len()
        || (!snapshot && integration.bounds.calls == 0)
        || integration.bounds.source_bytes == 0
        || integration.bounds.source_bytes > 1024 * 1024
        || integration.bounds.request_bytes == 0
        || integration.bounds.concurrency == 0
        || integration.bounds.concurrency > 16
    {
        bail!("integration bounds are inconsistent with its fixed operation graph");
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
    records: &BTreeMap<String, LoadedRecordsDefinition>,
    environment: &EnvironmentDocument,
) -> Result<()> {
    let (requires_relay, requires_notary) = project_product_topology(project);
    if environment.deployment.relay.is_some() != requires_relay
        || environment.relay.is_some() != requires_relay
    {
        bail!("environment Relay bindings must exactly match the project topology");
    }
    if environment.deployment.notary.is_some() != requires_notary
        || environment.issuance.is_some() != requires_notary
    {
        bail!("environment Notary bindings must exactly match the project topology");
    }
    if environment.notary_relay.is_some() != (requires_relay && requires_notary) {
        bail!("the Notary-to-Relay connection is required exactly for combined deployments");
    }
    if environment.version != 1 || environment.integrations.len() != integrations.len() {
        bail!("environment must bind every integration exactly once");
    }
    for (alias, loaded) in integrations {
        let binding = environment
            .integrations
            .get(alias)
            .ok_or_else(|| anyhow!("environment is missing integration binding {alias}"))?;
        if !loaded
            .document
            .source
            .versions
            .tested
            .contains(&binding.source_version)
            && !loaded
                .document
                .source
                .versions
                .supported
                .contains(&binding.source_version)
            && !loaded
                .document
                .source
                .versions
                .unverified
                .contains(&binding.source_version)
        {
            bail!("environment source_version is not declared by the integration");
        }
        match &loaded.document.capability {
            CapabilityDeclaration::Snapshot { .. } => {
                if binding.data_destination.is_some() || binding.credential_destination.is_some() {
                    bail!("snapshot uses only its governed records entity binding");
                }
            }
            CapabilityDeclaration::Http { .. }
            | CapabilityDeclaration::Script { .. } => {
                if binding.data_destination.is_none() {
                    bail!("HTTP integrations require a fixed data destination");
                }
                validate_https_origin(
                    &binding
                        .data_destination
                        .as_ref()
                        .expect("presence was checked")
                        .origin,
                    "data destination",
                )?;
            }
        }
        validate_environment_credential(credential_interface(&loaded.document), binding)?;
    }
    if environment
        .integrations
        .values()
        .filter_map(|binding| binding.data_destination.as_ref())
        .map(|destination| destination.origin.as_str())
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
    if environment.entities.len() != records.len() {
        bail!("environment must bind every governed records entity exactly once");
    }
    for (id, loaded) in records {
        let binding = environment
            .entities
            .get(id)
            .ok_or_else(|| anyhow!("environment is missing governed records entity {id}"))?;
        validate_environment_entity(&loaded.document, binding)?;
    }
    if environment
        .entities
        .keys()
        .any(|entity| !records.contains_key(entity))
    {
        bail!("environment contains an unknown governed records entity");
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
        validate_stable_id(&issuance.signing_kid, "issuance signing_kid")?;
        if issuance.generation == 0 {
            bail!("issuance generation must be positive");
        }
    }
    if let Some(relay) = &environment.relay {
        validate_https_origin(&relay.origin, "Relay origin")?;
        validate_https_origin(&relay.issuer, "Relay workload issuer")?;
        validate_token(&relay.audience, "Relay workload audience", 256)?;
        validate_token(
            &relay.workload_client_id,
            "Relay workload client id",
            256,
        )?;
        let jwks = url::Url::parse(&relay.jwks_url)
            .context("Relay workload JWKS URL is invalid")?;
        if jwks.scheme() != "https"
            || jwks.host().is_none()
            || !jwks.username().is_empty()
            || jwks.password().is_some()
            || jwks.path() == "/"
            || jwks.query().is_some()
            || jwks.fragment().is_some()
        {
            bail!("Relay workload JWKS URL must be one exact HTTPS resource");
        }
    }
    if let Some(connection) = &environment.notary_relay {
        validate_absolute_runtime_path(&connection.token_file, "Relay workload token file")?;
    }
    if let Some(relay) = &environment.deployment.relay {
        validate_stable_id(&relay.service, "Relay service id")?;
    }
    if let Some(notary) = &environment.deployment.notary {
        validate_stable_id(&notary.service, "Notary service id")?;
    }
    for (alias, loaded) in integrations {
        let enablement = environment.integrations[alias]
            .advanced_capabilities
            .as_ref()
            .map(|advanced| &advanced.script);
        match (&loaded.document.capability, enablement) {
            (CapabilityDeclaration::Script { script }, Some(enablement))
                if enablement.enabled
                    && enablement.review == ReviewClassInput::OperatorSecurity
                    && script.runtime == ScriptRuntime::RhaiV1
                    && is_script_runtime_released(ReleasedScriptRuntime::RhaiV1) => {}
            (CapabilityDeclaration::Script { .. }, _) => {
                bail!("script requires a released authoring contract and explicit operator-security enablement")
            }
            (_, None) => {}
            (_, Some(_)) => bail!("advanced capability enablement is unused"),
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
        || project.services.values().any(|service| {
            service.kind == ServiceKind::RecordsApi || !service.consultations.is_empty()
        });
    (requires_relay, requires_notary)
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
        CredentialType::None
        | CredentialType::Basic
        | CredentialType::StaticBearer
        | CredentialType::Oauth2ClientCredentials => {
            if interface.name.is_some() || interface.max_value_bytes.is_some() {
                bail!("non-API-key credential interfaces cannot declare API-key fields");
            }
        }
    }
    Ok(())
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
    records: &RecordsDefinition,
    binding: &EnvironmentEntityBinding,
) -> Result<()> {
    let expected = records
        .fields
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
    validate_token(&binding.source_revision, "records source revision", 256)?;
    validate_token(&binding.generation, "records generation", 256)?;
    let path = match &binding.provider {
        RecordProvider::Csv { path, .. }
        | RecordProvider::Xlsx { path, .. }
        | RecordProvider::Parquet { path } => path,
    };
    validate_absolute_runtime_path(path, "records provider path")?;
    if let RecordProvider::Xlsx { sheet, .. } = &binding.provider {
        validate_token(sheet, "records provider sheet", 256)?;
    }
    Ok(())
}
