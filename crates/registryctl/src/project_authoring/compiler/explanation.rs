// SPDX-License-Identifier: Apache-2.0

// Classifier-safe project explanation generation.
//
// The producer deliberately starts from the authored documents and the
// published field-knowledge index. Product configs, generated hashes, secret
// locators, and lowered request construction never cross this boundary.

struct ExplanationSchemaSet {
    documents: BTreeMap<knowledge::SchemaKind, Value>,
    index: knowledge::FieldKnowledgeIndex,
}

#[derive(Clone)]
enum ExplanationAddressScope {
    Project,
    Integration(String),
    Entity(String),
    Environment(String),
    Fixture {
        integration: String,
        fixture: String,
    },
}

impl ExplanationAddressScope {
    fn address(&self, path: &str) -> Result<ProjectFieldAddress> {
        let path = JsonPointer::new(path.to_owned())
            .map_err(|error| anyhow!("explanation field address is invalid: {error}"))?;
        Ok(match self {
            Self::Project => ProjectFieldAddress::Project { path },
            Self::Integration(integration) => ProjectFieldAddress::Integration {
                integration: integration.clone(),
                path,
            },
            Self::Entity(entity) => ProjectFieldAddress::Entity {
                entity: entity.clone(),
                path,
            },
            Self::Environment(environment) => ProjectFieldAddress::Environment {
                environment: environment.clone(),
                path,
            },
            Self::Fixture {
                integration,
                fixture,
            } => ProjectFieldAddress::Fixture {
                integration: integration.clone(),
                fixture: fixture.clone(),
                path,
            },
        })
    }

    fn sort_key(&self, path: &str) -> String {
        match self {
            Self::Project => format!("0\0{path}"),
            Self::Integration(integration) => format!("1\0{integration}\0{path}"),
            Self::Entity(entity) => format!("2\0{entity}\0{path}"),
            Self::Environment(environment) => format!("3\0{environment}\0{path}"),
            Self::Fixture {
                integration,
                fixture,
            } => format!("4\0{integration}\0{fixture}\0{path}"),
        }
    }
}

#[derive(Clone, Copy)]
enum ExplanationSource {
    Authored,
    Defaulted,
    Derived { semantic_rule_id: &'static str },
    EnvironmentBound,
}

impl ExplanationSource {
    const fn kind(self) -> FieldSourceKind {
        match self {
            Self::Authored => FieldSourceKind::Authored,
            Self::Defaulted => FieldSourceKind::Defaulted,
            Self::Derived { .. } => FieldSourceKind::Derived,
            Self::EnvironmentBound => FieldSourceKind::EnvironmentBound,
        }
    }

    const fn presence(self) -> FieldPresence {
        match self {
            Self::Authored => FieldPresence::Authored,
            Self::Defaulted => FieldPresence::Defaulted,
            Self::Derived { .. } => FieldPresence::Derived,
            Self::EnvironmentBound => FieldPresence::EnvironmentBound,
        }
    }

    const fn semantic_rule_id(self) -> Option<&'static str> {
        match self {
            Self::Derived { semantic_rule_id } => Some(semantic_rule_id),
            Self::Authored | Self::Defaulted | Self::EnvironmentBound => None,
        }
    }
}

#[derive(Clone, Debug)]
enum ExplanationScalar {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    Float(f64),
    Text(String),
}

impl ExplanationScalar {
    fn from_json(value: &Value) -> Option<Self> {
        match value {
            Value::Bool(value) => Some(Self::Boolean(*value)),
            Value::Number(value) => value
                .as_i64()
                .map(Self::Signed)
                .or_else(|| value.as_u64().map(Self::Unsigned))
                .or_else(|| value.as_f64().map(Self::Float)),
            Value::String(value) => Some(Self::Text(value.clone())),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        }
    }

    fn into_classifier_json(self) -> Value {
        match self {
            Self::Boolean(value) => Value::Bool(value),
            Self::Signed(value) => Value::Number(value.into()),
            Self::Unsigned(value) => Value::Number(value.into()),
            Self::Float(value) => serde_json::Number::from_f64(value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Self::Text(value) => Value::String(value),
        }
    }
}

/// The only non-public values allowed to cross the classifier boundary.
///
/// Call sites must identify the semantic class instead of passing arbitrary
/// JSON. Free-form request data, source values, and operational metadata have
/// no variant here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApprovedSemanticValue {
    Capability,
    Count,
    DeclarationClass,
    DisclosureClass,
    HumanIntent,
    Limit,
    Policy,
    ProductTopology,
}

struct PendingExplanationField {
    scope: ExplanationAddressScope,
    data_path: String,
    schema_kind: knowledge::SchemaKind,
    schema_path: String,
    source: ExplanationSource,
    value: Option<ExplanationScalar>,
    approval: Option<ApprovedSemanticValue>,
    default: Option<(FieldDefaultSource, bool, ExplanationScalar)>,
}

struct ExplanationBuilder<'a> {
    schemas: &'a ExplanationSchemaSet,
    fields: BTreeMap<String, ProjectFieldExplanation>,
}

impl<'a> ExplanationBuilder<'a> {
    fn new(schemas: &'a ExplanationSchemaSet) -> Self {
        Self {
            schemas,
            fields: BTreeMap::new(),
        }
    }

    fn add(&mut self, pending: PendingExplanationField) -> Result<()> {
        let field_path = knowledge::FieldPath {
            schema: pending.schema_kind,
            pointer: pending.schema_path.clone(),
        };
        let field_knowledge = self
            .schemas
            .index
            .by_path()
            .get(&field_path)
            .ok_or_else(|| anyhow!("published field knowledge is absent for {field_path}"))?;
        let address = pending.scope.address(&pending.data_path)?;
        let source_address = matches!(
            pending.source,
            ExplanationSource::Authored | ExplanationSource::EnvironmentBound
        )
        .then(|| address.clone());
        let reported_value =
            classifier_safe_value(field_knowledge, pending.value, pending.approval);
        let default = pending.default.map(|(source, applied, value)| {
            let reported_value =
                classifier_safe_value(field_knowledge, Some(value), pending.approval);
            ProjectFieldDefault {
                source,
                applied,
                reported_value: Some(reported_value),
            }
        });
        let semantic_rule_ids = field_knowledge
            .semantic_rules
            .iter()
            .map(|rule| knowledge_semantic_rule_id(*rule).to_owned())
            .collect();
        let explanation = ProjectFieldExplanation {
            address,
            source: ProjectFieldSource {
                kind: pending.source.kind(),
                address: source_address,
                semantic_rule_id: pending.source.semantic_rule_id().map(str::to_owned),
            },
            state: ProjectFieldState {
                presence: pending.source.presence(),
                effect: FieldEffect::Effective,
            },
            default,
            constraints: ProjectFieldConstraints {
                schema_refs: vec![ProjectSchemaRef {
                    schema: report_schema_kind(pending.schema_kind),
                    path: JsonPointer::new(pending.schema_path.clone()).map_err(|error| {
                        anyhow!("explanation schema reference is invalid: {error}")
                    })?,
                }],
                semantic_rule_ids,
            },
            knowledge: report_field_knowledge(field_knowledge),
            reported_value,
        };
        self.fields
            .insert(pending.scope.sort_key(&pending.data_path), explanation);
        Ok(())
    }

    fn add_authored_document(
        &mut self,
        schema_kind: knowledge::SchemaKind,
        scope: ExplanationAddressScope,
        document: &Value,
        source: ExplanationSource,
    ) -> Result<()> {
        let schema = self
            .schemas
            .documents
            .get(&schema_kind)
            .ok_or_else(|| anyhow!("published {schema_kind} schema is absent"))?;
        let mut pending = Vec::new();
        walk_authored_explanation(
            schema,
            schema,
            "",
            document,
            "",
            schema_kind,
            &scope,
            source,
            &mut pending,
        )?;
        for field in pending {
            self.add(field)?;
        }
        Ok(())
    }

    fn finish(self) -> Vec<ProjectFieldExplanation> {
        self.fields.into_values().collect()
    }
}

fn explanation_schema_set() -> Result<ExplanationSchemaSet> {
    let mut documents = BTreeMap::new();
    for (kind, source) in [
        (
            knowledge::SchemaKind::Project,
            include_str!("../../../schemas/project-authoring/project.schema.json"),
        ),
        (
            knowledge::SchemaKind::Environment,
            include_str!("../../../schemas/project-authoring/environment.schema.json"),
        ),
        (
            knowledge::SchemaKind::Integration,
            include_str!("../../../schemas/project-authoring/integration.schema.json"),
        ),
        (
            knowledge::SchemaKind::Fixture,
            include_str!("../../../schemas/project-authoring/fixture.schema.json"),
        ),
        (
            knowledge::SchemaKind::Entity,
            include_str!("../../../schemas/project-authoring/entity.schema.json"),
        ),
    ] {
        let schema =
            serde_json::from_str(source).with_context(|| format!("published {kind} schema"))?;
        documents.insert(kind, schema);
    }
    let index = knowledge::published_field_knowledge_index()
        .context("published field knowledge is inconsistent")?;
    Ok(ExplanationSchemaSet { documents, index })
}

fn authored_explanation_document(loaded: &LoadedRegistryProject, path: &Path) -> Result<Value> {
    let bytes = read_authored_file(&loaded.root, path)?;
    let relative = path
        .strip_prefix(&loaded.root)
        .map_err(|_| anyhow!("authored explanation input escapes the project root"))?;
    let relative = relative
        .to_str()
        .ok_or_else(|| anyhow!("authored explanation input path is not Unicode"))?;
    let relative = ProjectRelativePath::new(relative.to_owned())
        .map_err(|error| anyhow!("authored explanation input path is invalid: {error}"))?;
    let expected = loaded
        .artifact_inputs
        .iter()
        .find(|input| input.path == relative)
        .ok_or_else(|| anyhow!("authored explanation input is absent from the loaded project"))?;
    let actual = sha256_uri(&bytes);
    if expected.digest.as_str() != actual {
        bail!("authored explanation input changed after the project was loaded");
    }
    serde_norway::from_slice(&bytes).context("authored explanation input did not parse")
}

fn generated_explanation(
    loaded: &LoadedRegistryProject,
    environment_name: &str,
) -> Result<ProjectExplanationReportV1> {
    let schemas = explanation_schema_set()?;
    let mut builder = ExplanationBuilder::new(&schemas);

    let project_document = authored_explanation_document(loaded, &loaded.root.join(PROJECT_FILE))?;
    builder.add_authored_document(
        knowledge::SchemaKind::Project,
        ExplanationAddressScope::Project,
        &project_document,
        ExplanationSource::Authored,
    )?;

    for (entity_id, reference) in &loaded.project.entities {
        let path = resolve_authored_path(&loaded.root, &reference.file)?;
        let document = authored_explanation_document(loaded, &path)?;
        builder.add_authored_document(
            knowledge::SchemaKind::Entity,
            ExplanationAddressScope::Entity(entity_id.clone()),
            &document,
            ExplanationSource::Authored,
        )?;
    }

    for (integration_id, reference) in &loaded.project.integrations {
        let path = resolve_authored_path(&loaded.root, &reference.file)?;
        let document = authored_explanation_document(loaded, &path)?;
        builder.add_authored_document(
            knowledge::SchemaKind::Integration,
            ExplanationAddressScope::Integration(integration_id.clone()),
            &document,
            ExplanationSource::Authored,
        )?;
        add_effective_integration_fields(
            &mut builder,
            integration_id,
            &loaded.integrations[integration_id].document,
            &document,
        )?;
        for (fixture_path, fixture) in &loaded.integrations[integration_id].fixtures {
            let document = authored_explanation_document(loaded, fixture_path)?;
            builder.add_authored_document(
                knowledge::SchemaKind::Fixture,
                ExplanationAddressScope::Fixture {
                    integration: integration_id.clone(),
                    fixture: fixture.name.clone(),
                },
                &document,
                ExplanationSource::Authored,
            )?;
        }
    }

    add_project_topology_fields(&mut builder, loaded)?;
    if let (Some(loaded_environment_name), Some(environment)) = (
        loaded.environment_name.as_deref(),
        loaded.environment.as_ref(),
    ) {
        if loaded_environment_name == environment_name {
            let environment_path = resolve_authored_path(
                &loaded.root,
                &PathBuf::from("environments").join(format!("{environment_name}.yaml")),
            )?;
            let environment_document = authored_explanation_document(loaded, &environment_path)?;
            builder.add_authored_document(
                knowledge::SchemaKind::Environment,
                ExplanationAddressScope::Environment(environment_name.to_owned()),
                &environment_document,
                ExplanationSource::EnvironmentBound,
            )?;
            add_environment_effective_fields(
                &mut builder,
                environment_name,
                environment,
                &environment_document,
            )?;
        }
    }

    Ok(ProjectExplanationReportV1 {
        schema_version: ProjectExplanationSchemaVersion::V1,
        project: loaded.project.registry.id.clone(),
        environment: environment_name.to_owned(),
        fields: builder.finish(),
    })
}

/// Select directly authored, non-secret scalars for an explicit trusted-local
/// terminal review.
///
/// The classifier-safe explanation remains the authority for each field's
/// source and sensitivity. This function only joins approved addresses back to
/// digest-checked authored documents. It intentionally excludes fixtures,
/// defaults, derived values, and every secret-bearing classification.
fn trusted_local_authored_values(
    loaded: &LoadedRegistryProject,
    explanation: &ProjectExplanationReportV1,
) -> Result<Vec<ProjectTrustedLocalAuthoredValue>> {
    let project_document = authored_explanation_document(loaded, &loaded.root.join(PROJECT_FILE))?;
    let mut integration_documents = BTreeMap::new();
    for (integration_id, reference) in &loaded.project.integrations {
        let path = resolve_authored_path(&loaded.root, &reference.file)?;
        integration_documents.insert(
            integration_id.as_str(),
            authored_explanation_document(loaded, &path)?,
        );
    }
    let mut entity_documents = BTreeMap::new();
    for (entity_id, reference) in &loaded.project.entities {
        let path = resolve_authored_path(&loaded.root, &reference.file)?;
        entity_documents.insert(
            entity_id.as_str(),
            authored_explanation_document(loaded, &path)?,
        );
    }
    let environment_document = if let Some(environment_name) = loaded.environment_name.as_deref() {
        let path = resolve_authored_path(
            &loaded.root,
            &PathBuf::from("environments").join(format!("{environment_name}.yaml")),
        )?;
        Some((
            environment_name,
            authored_explanation_document(loaded, &path)?,
        ))
    } else {
        None
    };

    let mut values = Vec::new();
    for field in &explanation.fields {
        if !matches!(
            field.source.kind,
            FieldSourceKind::Authored | FieldSourceKind::EnvironmentBound
        ) || field.source.address.as_ref() != Some(&field.address)
            || !matches!(
                field.state.presence,
                FieldPresence::Authored | FieldPresence::EnvironmentBound
            )
            || !matches!(
                field.knowledge.sensitivity,
                FieldSensitivity::Public
                    | FieldSensitivity::Internal
                    | FieldSensitivity::Structural
                    | FieldSensitivity::Sensitive
            )
        {
            continue;
        }
        if trusted_local_value_path_is_prohibited(&field.address) {
            continue;
        }
        let (document, path) = match &field.address {
            ProjectFieldAddress::Project { path } => (&project_document, path),
            ProjectFieldAddress::Integration { integration, path } => {
                let Some(document) = integration_documents.get(integration.as_str()) else {
                    continue;
                };
                (document, path)
            }
            ProjectFieldAddress::Entity { entity, path } => {
                let Some(document) = entity_documents.get(entity.as_str()) else {
                    continue;
                };
                (document, path)
            }
            ProjectFieldAddress::Environment { environment, path } => {
                let Some((loaded_environment, document)) = environment_document.as_ref() else {
                    continue;
                };
                if environment != loaded_environment {
                    continue;
                }
                (document, path)
            }
            // Fixture documents may contain planted private inputs or source
            // responses. The trusted-local switch never weakens that boundary.
            ProjectFieldAddress::Fixture { .. } => continue,
        };
        let Some(value) = document.pointer(path.as_str()) else {
            continue;
        };
        if !matches!(value, Value::Bool(_) | Value::Number(_) | Value::String(_)) {
            continue;
        }
        values.push(ProjectTrustedLocalAuthoredValue {
            address: field.address.clone(),
            source: field.source.kind,
            sensitivity: field.knowledge.sensitivity,
            value: value.clone(),
        });
    }
    Ok(values)
}

#[cfg(test)]
pub(crate) fn generated_explanation_for_test(
    root: &Path,
    environment_name: &str,
) -> Result<ProjectExplanationReportV1> {
    let loaded = load_registry_project(root, Some(environment_name))?;
    generated_explanation(&loaded, environment_name)
}

fn add_project_topology_fields(
    builder: &mut ExplanationBuilder<'_>,
    loaded: &LoadedRegistryProject,
) -> Result<()> {
    let scope = ExplanationAddressScope::Project;
    let (requires_relay, requires_notary) = project_product_topology(&loaded.project);
    let topology = match (requires_relay, requires_notary) {
        (true, false) => "relay_only",
        (false, true) => "notary_only",
        (true, true) => "combined",
        (false, false) => "none",
    };
    add_derived_scalar(
        builder,
        &scope,
        "/topology/deployment",
        knowledge::SchemaKind::Project,
        "/properties/services",
        ExplanationScalar::Text(topology.to_owned()),
        ApprovedSemanticValue::ProductTopology,
        "compiler.product_topology",
    )?;
    for (path, schema_path, count) in [
        (
            "/topology/source_integration_count",
            "/properties/integrations",
            loaded.integrations.len(),
        ),
        (
            "/topology/materialized_entity_count",
            "/properties/entities",
            loaded.entities.len(),
        ),
        (
            "/topology/service_count",
            "/properties/services",
            loaded.project.services.len(),
        ),
        (
            "/topology/records_api_service_count",
            "/properties/services",
            loaded
                .project
                .services
                .values()
                .filter(|service| service.kind == ServiceKind::RecordsApi)
                .count(),
        ),
        (
            "/topology/evidence_service_count",
            "/properties/services",
            loaded
                .project
                .services
                .values()
                .filter(|service| service.kind == ServiceKind::Evidence)
                .count(),
        ),
    ] {
        add_derived_scalar(
            builder,
            &scope,
            path,
            knowledge::SchemaKind::Project,
            schema_path,
            ExplanationScalar::Unsigned(count as u64),
            ApprovedSemanticValue::Count,
            "compiler.topology_count",
        )?;
    }
    for (service_id, service) in &loaded.project.services {
        for (name, count) in [
            ("consultation_count", service.consultations.len()),
            ("claim_count", service.claims.len()),
            (
                "credential_profile_count",
                service.credential_profiles.len(),
            ),
        ] {
            add_derived_scalar(
                builder,
                &scope,
                &format!(
                    "/services/{}/{name}",
                    escape_explanation_pointer_segment(service_id)
                ),
                knowledge::SchemaKind::Project,
                "/properties/services",
                ExplanationScalar::Unsigned(count as u64),
                ApprovedSemanticValue::Count,
                "compiler.service_contract_count",
            )?;
        }
        for (claim_id, claim) in &service.claims {
            // This is the compiler's authored dependency classification. It
            // does not assert live Relay activation or interoperability.
            let evidence = match inferred_claim_evidence(service, claim)? {
                ClaimEvidence::RegistryBacked => "registry_backed",
                ClaimEvidence::SelfAttested => "self_attested",
            };
            add_derived_scalar(
                builder,
                &scope,
                &format!(
                    "/services/{}/claims/{}/evidence",
                    escape_explanation_pointer_segment(service_id),
                    escape_explanation_pointer_segment(claim_id)
                ),
                knowledge::SchemaKind::Project,
                "/$defs/evidenceService/properties/claims",
                ExplanationScalar::Text(evidence.to_owned()),
                ApprovedSemanticValue::DeclarationClass,
                "compiler.claim_evidence_dependency",
            )?;
        }
    }
    Ok(())
}

fn add_effective_integration_fields(
    builder: &mut ExplanationBuilder<'_>,
    integration_id: &str,
    integration: &IntegrationDocument,
    authored: &Value,
) -> Result<()> {
    let scope = ExplanationAddressScope::Integration(integration_id.to_owned());
    let effective_limit = |builder: &mut ExplanationBuilder<'_>,
                           path: &str,
                           schema_path: &str,
                           value: ExplanationScalar,
                           authored: bool,
                           default: ExplanationScalar|
     -> Result<()> {
        builder.add(PendingExplanationField {
            scope: scope.clone(),
            data_path: path.to_owned(),
            schema_kind: knowledge::SchemaKind::Integration,
            schema_path: schema_path.to_owned(),
            source: if authored {
                ExplanationSource::Authored
            } else {
                ExplanationSource::Defaulted
            },
            value: Some(value),
            approval: Some(ApprovedSemanticValue::Limit),
            default: Some((FieldDefaultSource::Compiler, !authored, default)),
        })
    };
    effective_limit(
        builder,
        "/limits/request_bytes",
        "/$defs/limits/properties/request_bytes",
        ExplanationScalar::Unsigned(u64::from(integration.bounds.request_bytes)),
        integration.bounds.request_bytes_authored,
        ExplanationScalar::Unsigned(DEFAULT_REQUEST_BYTES),
    )?;
    effective_limit(
        builder,
        "/limits/source_bytes",
        "/$defs/limits/properties/source_bytes",
        ExplanationScalar::Unsigned(integration.bounds.source_bytes),
        integration.bounds.source_bytes_authored,
        ExplanationScalar::Unsigned(DEFAULT_SOURCE_BYTES),
    )?;
    effective_limit(
        builder,
        "/limits/deadline",
        "/$defs/limits/properties/deadline",
        ExplanationScalar::Text(integration.bounds.deadline.clone()),
        integration.bounds.deadline_authored,
        ExplanationScalar::Text(DEFAULT_DEADLINE.to_owned()),
    )?;

    match &integration.capability {
        CapabilityDeclaration::Http { http } => {
            add_derived_scalar(
                builder,
                &scope,
                "/capability/type",
                knowledge::SchemaKind::Integration,
                "/$defs/capability/oneOf/0/properties/http",
                ExplanationScalar::Text("http".to_owned()),
                ApprovedSemanticValue::Capability,
                "compiler.capability_class",
            )?;
            add_derived_scalar(
                builder,
                &scope,
                "/capability/http/operation_count",
                knowledge::SchemaKind::Integration,
                "/$defs/capability/oneOf/0/properties/http",
                ExplanationScalar::Unsigned(http.operations.len() as u64),
                ApprovedSemanticValue::Count,
                "compiler.lowered_operation_count",
            )?;
            for (index, operation) in http.operations.values().enumerate() {
                add_derived_scalar(
                    builder,
                    &scope,
                    &format!("/capability/http/operations/{index}/role"),
                    knowledge::SchemaKind::Integration,
                    "/$defs/capability/oneOf/0/properties/http",
                    ExplanationScalar::Text(
                        match operation.role {
                            OperationRole::Data => "data",
                            OperationRole::Credential => "credential",
                            OperationRole::Verification => "verification",
                        }
                        .to_owned(),
                    ),
                    ApprovedSemanticValue::DeclarationClass,
                    "compiler.lowered_operation_role",
                )?;
            }
            builder.add(PendingExplanationField {
                scope: scope.clone(),
                data_path: "/limits/calls".to_owned(),
                schema_kind: knowledge::SchemaKind::Integration,
                schema_path: "/$defs/limits/properties/calls".to_owned(),
                source: if integration.bounds.calls_authored {
                    ExplanationSource::Authored
                } else {
                    ExplanationSource::Derived {
                        semantic_rule_id: "compiler.http_single_call",
                    }
                },
                value: Some(ExplanationScalar::Unsigned(1)),
                approval: Some(ApprovedSemanticValue::Limit),
                default: Some((
                    FieldDefaultSource::SemanticRule,
                    !integration.bounds.calls_authored,
                    ExplanationScalar::Unsigned(1),
                )),
            })?;
            let response_max_bytes = http
                .operations
                .values()
                .find(|operation| operation.role == OperationRole::Data)
                .map_or(DEFAULT_SOURCE_RESPONSE_BYTES, |operation| {
                    u64::from(operation.response.max_bytes)
                });
            effective_limit(
                builder,
                "/source/response/max_bytes",
                "/$defs/source/properties/response/properties/max_bytes",
                ExplanationScalar::Unsigned(response_max_bytes),
                http.response_max_bytes_authored,
                ExplanationScalar::Unsigned(DEFAULT_SOURCE_RESPONSE_BYTES),
            )?;
            add_effective_response_format(
                builder,
                &scope,
                "json",
                authored.pointer("/source/response/format").is_some(),
            )?;
        }
        CapabilityDeclaration::Script { script } => {
            add_derived_scalar(
                builder,
                &scope,
                "/capability/type",
                knowledge::SchemaKind::Integration,
                "/$defs/capability/oneOf/1/properties/script",
                ExplanationScalar::Text("script".to_owned()),
                ApprovedSemanticValue::Capability,
                "compiler.capability_class",
            )?;
            effective_limit(
                builder,
                "/limits/calls",
                "/$defs/limits/properties/calls",
                ExplanationScalar::Unsigned(u64::from(integration.bounds.calls)),
                integration.bounds.calls_authored,
                ExplanationScalar::Unsigned(u64::from(DEFAULT_SCRIPT_CALLS)),
            )?;
            effective_limit(
                builder,
                "/source/response/max_bytes",
                "/$defs/source/properties/response/properties/max_bytes",
                ExplanationScalar::Unsigned(u64::from(script.response.max_bytes)),
                script.response.max_bytes_authored,
                ExplanationScalar::Unsigned(DEFAULT_SOURCE_RESPONSE_BYTES),
            )?;
            add_effective_response_format(
                builder,
                &scope,
                match script.response.format {
                    AuthoredResponseFormat::Json => "json",
                    AuthoredResponseFormat::Text => "text",
                },
                authored.pointer("/source/response/format").is_some(),
            )?;
        }
        CapabilityDeclaration::Snapshot { .. } => {
            add_derived_scalar(
                builder,
                &scope,
                "/capability/type",
                knowledge::SchemaKind::Integration,
                "/$defs/capability/oneOf/2/properties/snapshot",
                ExplanationScalar::Text("snapshot".to_owned()),
                ApprovedSemanticValue::Capability,
                "compiler.capability_class",
            )?;
        }
    }
    Ok(())
}

fn add_effective_response_format(
    builder: &mut ExplanationBuilder<'_>,
    scope: &ExplanationAddressScope,
    format: &str,
    authored: bool,
) -> Result<()> {
    builder.add(PendingExplanationField {
        scope: scope.clone(),
        data_path: "/source/response/format".to_owned(),
        schema_kind: knowledge::SchemaKind::Integration,
        schema_path: "/$defs/source/properties/response/properties/format".to_owned(),
        source: if authored {
            ExplanationSource::Authored
        } else {
            ExplanationSource::Defaulted
        },
        value: Some(ExplanationScalar::Text(format.to_owned())),
        approval: Some(ApprovedSemanticValue::DeclarationClass),
        default: Some((
            FieldDefaultSource::Compiler,
            !authored,
            ExplanationScalar::Text("json".to_owned()),
        )),
    })
}

fn add_environment_effective_fields(
    builder: &mut ExplanationBuilder<'_>,
    environment_name: &str,
    environment: &EnvironmentDocument,
    authored: &Value,
) -> Result<()> {
    let scope = ExplanationAddressScope::Environment(environment_name.to_owned());
    for (path, present) in [
        (
            "/topology/relay_bound",
            environment.deployment.relay.is_some(),
        ),
        (
            "/topology/notary_bound",
            environment.deployment.notary.is_some(),
        ),
    ] {
        add_derived_scalar(
            builder,
            &scope,
            path,
            knowledge::SchemaKind::Environment,
            "/properties/deployment",
            ExplanationScalar::Boolean(present),
            ApprovedSemanticValue::ProductTopology,
            "compiler.environment_product_binding",
        )?;
    }
    for (integration_id, integration) in &environment.integrations {
        add_derived_scalar(
            builder,
            &scope,
            &format!(
                "/integrations/{}/source/credential_class",
                escape_explanation_pointer_segment(integration_id)
            ),
            knowledge::SchemaKind::Environment,
            "/$defs/source/properties/credential",
            ExplanationScalar::Text(
                match &integration.source.credential {
                    Some(credential) if credential.username.is_some() => "basic",
                    Some(credential) if credential.token.is_some() => "static_bearer",
                    Some(credential) if credential.client_id.is_some() => {
                        "oauth2_client_credentials"
                    }
                    Some(credential) if credential.value.is_some() => "api_key",
                    Some(_) => "configured",
                    None => "none",
                }
                .to_owned(),
            ),
            ApprovedSemanticValue::DeclarationClass,
            "compiler.credential_class",
        )?;
    }
    if let Some(issuance) = &environment.issuance {
        add_effective_environment_default(
            builder,
            &scope,
            "/issuance/algorithm",
            "/properties/issuance/properties/algorithm",
            ExplanationScalar::Text(issuance.algorithm.as_str().to_owned()),
            ExplanationScalar::Text("EdDSA".to_owned()),
            authored.pointer("/issuance/algorithm").is_some(),
            ApprovedSemanticValue::DeclarationClass,
        )?;
    }
    if let Some(oid4vci) = &environment.oid4vci {
        add_effective_environment_default(
            builder,
            &scope,
            "/oid4vci/tx_code/required",
            "/$defs/oid4vci/properties/tx_code/properties/required",
            ExplanationScalar::Boolean(oid4vci.tx_code.required),
            ExplanationScalar::Boolean(true),
            authored.pointer("/oid4vci/tx_code/required").is_some(),
            ApprovedSemanticValue::Policy,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_effective_environment_default(
    builder: &mut ExplanationBuilder<'_>,
    scope: &ExplanationAddressScope,
    data_path: &str,
    schema_path: &str,
    value: ExplanationScalar,
    default: ExplanationScalar,
    authored: bool,
    approval: ApprovedSemanticValue,
) -> Result<()> {
    builder.add(PendingExplanationField {
        scope: scope.clone(),
        data_path: data_path.to_owned(),
        schema_kind: knowledge::SchemaKind::Environment,
        schema_path: schema_path.to_owned(),
        source: if authored {
            ExplanationSource::EnvironmentBound
        } else {
            ExplanationSource::Defaulted
        },
        value: Some(value),
        approval: Some(approval),
        default: Some((FieldDefaultSource::AuthoringSchema, !authored, default)),
    })
}

#[allow(clippy::too_many_arguments)]
fn add_derived_scalar(
    builder: &mut ExplanationBuilder<'_>,
    scope: &ExplanationAddressScope,
    data_path: &str,
    schema_kind: knowledge::SchemaKind,
    schema_path: &str,
    value: ExplanationScalar,
    approval: ApprovedSemanticValue,
    semantic_rule_id: &'static str,
) -> Result<()> {
    builder.add(PendingExplanationField {
        scope: scope.clone(),
        data_path: data_path.to_owned(),
        schema_kind,
        schema_path: schema_path.to_owned(),
        source: ExplanationSource::Derived { semantic_rule_id },
        value: Some(value),
        approval: Some(approval),
        default: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_authored_explanation(
    schema_document: &Value,
    schema_node: &Value,
    schema_path: &str,
    value: &Value,
    data_path: &str,
    schema_kind: knowledge::SchemaKind,
    scope: &ExplanationAddressScope,
    source: ExplanationSource,
    output: &mut Vec<PendingExplanationField>,
) -> Result<()> {
    let classification = schema_classification(schema_node);
    if classification.is_some_and(classification_is_always_redacted)
        || explanation_container_is_opaque(schema_kind, schema_path)
    {
        output.push(PendingExplanationField {
            scope: scope.clone(),
            data_path: data_path.to_owned(),
            schema_kind,
            schema_path: schema_path.to_owned(),
            source,
            value: None,
            approval: None,
            default: None,
        });
        return Ok(());
    }

    if let Some(scalar) = ExplanationScalar::from_json(value) {
        let default = schema_node
            .get("default")
            .and_then(ExplanationScalar::from_json)
            .map(|default| (FieldDefaultSource::AuthoringSchema, false, default));
        output.push(PendingExplanationField {
            scope: scope.clone(),
            data_path: data_path.to_owned(),
            schema_kind,
            schema_path: schema_path.to_owned(),
            source,
            approval: approved_authored_semantic_value(
                schema_kind,
                schema_path,
                data_path,
                &scalar,
            ),
            value: Some(scalar),
            default,
        });
        return Ok(());
    }

    match value {
        Value::Object(object) => {
            if schema_is_unclassified_open_object(schema_document, schema_node, object) {
                output.push(PendingExplanationField {
                    scope: scope.clone(),
                    data_path: data_path.to_owned(),
                    schema_kind,
                    schema_path: schema_path.to_owned(),
                    source,
                    value: None,
                    approval: None,
                    default: None,
                });
                return Ok(());
            }
            for (name, child) in object {
                let (child_schema, child_schema_path) = schema_for_object_property(
                    schema_document,
                    schema_node,
                    schema_path,
                    name,
                    object,
                )
                .ok_or_else(|| {
                    anyhow!(
                        "published {schema_kind} schema has no field for authored path {data_path}/{}",
                        escape_explanation_pointer_segment(name)
                    )
                })?;
                let child_path =
                    format!("{data_path}/{}", escape_explanation_pointer_segment(name));
                walk_authored_explanation(
                    schema_document,
                    child_schema,
                    &child_schema_path,
                    child,
                    &child_path,
                    schema_kind,
                    scope,
                    source,
                    output,
                )?;
            }
        }
        Value::Array(items) => {
            if !items.is_empty()
                && schema_for_array_item(schema_document, schema_node, schema_path, value, 0)
                    .is_none()
            {
                output.push(PendingExplanationField {
                    scope: scope.clone(),
                    data_path: data_path.to_owned(),
                    schema_kind,
                    schema_path: schema_path.to_owned(),
                    source,
                    value: None,
                    approval: None,
                    default: None,
                });
                return Ok(());
            }
            for (index, item) in items.iter().enumerate() {
                let (item_schema, item_schema_path) = schema_for_array_item(
                    schema_document,
                    schema_node,
                    schema_path,
                    value,
                    index,
                )
                .ok_or_else(|| {
                    anyhow!(
                        "published {schema_kind} schema has no item {index} for authored path {data_path}"
                    )
                })?;
                walk_authored_explanation(
                    schema_document,
                    item_schema,
                    &item_schema_path,
                    item,
                    &format!("{data_path}/{index}"),
                    schema_kind,
                    scope,
                    source,
                    output,
                )?;
            }
        }
        Value::Null => {}
        Value::Bool(_) | Value::Number(_) | Value::String(_) => unreachable!(),
    }
    Ok(())
}

fn schema_for_object_property<'a>(
    schema_document: &'a Value,
    schema_node: &'a Value,
    schema_path: &str,
    property: &str,
    instance: &Map<String, Value>,
) -> Option<(&'a Value, String)> {
    if let Some(property_schema) = schema_node
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(property))
    {
        return Some((
            property_schema,
            format!(
                "{schema_path}/properties/{}",
                escape_explanation_pointer_segment(property)
            ),
        ));
    }
    if let Some((resolved, resolved_path)) =
        resolve_local_schema_reference(schema_document, schema_node)
    {
        if let Some(found) = schema_for_object_property(
            schema_document,
            resolved,
            &resolved_path,
            property,
            instance,
        ) {
            return Some(found);
        }
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        let Some(branches) = schema_node.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        for (index, branch) in branches.iter().enumerate() {
            if keyword != "allOf" && !schema_branch_matches(schema_document, branch, instance) {
                continue;
            }
            let branch_path = format!("{schema_path}/{keyword}/{index}");
            if let Some(found) = schema_for_object_property(
                schema_document,
                branch,
                &branch_path,
                property,
                instance,
            ) {
                return Some(found);
            }
        }
    }
    schema_node
        .get("additionalProperties")
        .filter(|schema| schema.is_object())
        .map(|schema| (schema, format!("{schema_path}/additionalProperties")))
}

fn schema_for_array_item<'a>(
    schema_document: &'a Value,
    schema_node: &'a Value,
    schema_path: &str,
    instance: &Value,
    item_index: usize,
) -> Option<(&'a Value, String)> {
    if let Some(items) = schema_node.get("items").filter(|items| items.is_object()) {
        return Some((items, format!("{schema_path}/items")));
    }
    if let Some(item) = schema_node
        .get("prefixItems")
        .and_then(Value::as_array)
        .and_then(|items| items.get(item_index))
    {
        return Some((item, format!("{schema_path}/prefixItems/{item_index}")));
    }
    if let Some((resolved, resolved_path)) =
        resolve_local_schema_reference(schema_document, schema_node)
    {
        if let Some(found) = schema_for_array_item(
            schema_document,
            resolved,
            &resolved_path,
            instance,
            item_index,
        ) {
            return Some(found);
        }
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        let Some(branches) = schema_node.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        for (index, branch) in branches.iter().enumerate() {
            if keyword != "allOf"
                && !schema_type_matches(branch, instance)
                && resolve_local_schema_reference(schema_document, branch)
                    .is_none_or(|(resolved, _)| !schema_type_matches(resolved, instance))
            {
                continue;
            }
            let branch_path = format!("{schema_path}/{keyword}/{index}");
            if let Some(found) =
                schema_for_array_item(schema_document, branch, &branch_path, instance, item_index)
            {
                return Some(found);
            }
        }
    }
    None
}

fn resolve_local_schema_reference<'a>(
    schema_document: &'a Value,
    schema_node: &Value,
) -> Option<(&'a Value, String)> {
    let pointer = schema_node.get("$ref")?.as_str()?.strip_prefix('#')?;
    schema_document
        .pointer(pointer)
        .map(|schema| (schema, pointer.to_owned()))
}

fn schema_branch_matches(
    schema_document: &Value,
    branch: &Value,
    instance: &Map<String, Value>,
) -> bool {
    let branch = resolve_local_schema_reference(schema_document, branch)
        .map_or(branch, |(resolved, _)| resolved);
    let instance_value = Value::Object(instance.clone());
    if !schema_type_matches(branch, &instance_value)
        || branch
            .get("const")
            .is_some_and(|expected| expected != &instance_value)
    {
        return false;
    }
    if branch
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .any(|name| !instance.contains_key(name))
        })
    {
        return false;
    }
    let Some(properties) = branch.get("properties").and_then(Value::as_object) else {
        return true;
    };
    for (name, property_schema) in properties {
        let Some(actual) = instance.get(name) else {
            continue;
        };
        if property_schema
            .get("const")
            .is_some_and(|expected| expected != actual)
        {
            return false;
        }
    }
    true
}

fn schema_is_unclassified_open_object(
    schema_document: &Value,
    schema_node: &Value,
    instance: &Map<String, Value>,
) -> bool {
    if schema_node.get("type").and_then(Value::as_str) == Some("object")
        && schema_node
            .get("properties")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
        && schema_node.get("propertyNames").is_none()
        && schema_node
            .get("additionalProperties")
            .is_none_or(|additional| additional == &Value::Bool(true))
    {
        return true;
    }
    if let Some((resolved, _)) = resolve_local_schema_reference(schema_document, schema_node) {
        if schema_is_unclassified_open_object(schema_document, resolved, instance) {
            return true;
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        let Some(branches) = schema_node.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        if branches.iter().any(|branch| {
            schema_branch_matches(schema_document, branch, instance)
                && schema_is_unclassified_open_object(schema_document, branch, instance)
        }) {
            return true;
        }
    }
    false
}

fn schema_type_matches(schema: &Value, instance: &Value) -> bool {
    let Some(schema_type) = schema.get("type").and_then(Value::as_str) else {
        return true;
    };
    matches!(
        (schema_type, instance),
        ("object", Value::Object(_))
            | ("array", Value::Array(_))
            | ("string", Value::String(_))
            | ("integer" | "number", Value::Number(_))
            | ("boolean", Value::Bool(_))
            | ("null", Value::Null)
    )
}

fn schema_classification(schema: &Value) -> Option<&str> {
    schema.get(knowledge::FIELD_ANNOTATION_KEY)?.as_str()
}

fn classification_is_always_redacted(classification: &str) -> bool {
    matches!(
        classification,
        "sensitive_property"
            | "secret_reference_property"
            | "redacted_fixture_property"
            | "sensitive_array_item"
            | "redacted_fixture_array_item"
            | "redacted_fixture_map_key"
            | "redacted_fixture_map_value"
    )
}

fn explanation_container_is_opaque(schema_kind: knowledge::SchemaKind, schema_path: &str) -> bool {
    match schema_kind {
        knowledge::SchemaKind::Integration => matches!(
            schema_path,
            "/$defs/capability/oneOf/0/properties/http/properties/request"
                | "/$defs/source/properties/auth"
                | "/$defs/consultations/additionalProperties/properties/input"
        ),
        knowledge::SchemaKind::Project => {
            schema_path.ends_with("/properties/input")
                && schema_path.contains("/$defs/consultations/")
        }
        knowledge::SchemaKind::Environment => {
            schema_path.ends_with("/properties/provider")
                || schema_path.ends_with("/properties/credential")
        }
        knowledge::SchemaKind::Fixture | knowledge::SchemaKind::Entity => false,
    }
}

fn approved_authored_semantic_value(
    schema_kind: knowledge::SchemaKind,
    schema_path: &str,
    _data_path: &str,
    value: &ExplanationScalar,
) -> Option<ApprovedSemanticValue> {
    match schema_kind {
        knowledge::SchemaKind::Project => {
            if schema_path.ends_with("/properties/purpose")
                || schema_path.ends_with("/properties/legal_basis")
                || schema_path.ends_with("/properties/scopes/items")
            {
                Some(ApprovedSemanticValue::HumanIntent)
            } else if schema_path.ends_with("/properties/consent")
                || schema_path.ends_with("/properties/kind")
                || schema_path.ends_with("/properties/format")
                || schema_path.ends_with("/properties/value/properties/type")
            {
                Some(ApprovedSemanticValue::DeclarationClass)
            } else if schema_path.ends_with("/properties/disclosure")
                || schema_path.ends_with("/properties/default")
                || (schema_path.ends_with("/properties/allowed/items")
                    && schema_path.contains("disclosure"))
            {
                Some(ApprovedSemanticValue::DisclosureClass)
            } else if schema_path.ends_with("/properties/version")
                && !matches!(value, ExplanationScalar::Text(_))
            {
                Some(ApprovedSemanticValue::Count)
            } else {
                None
            }
        }
        knowledge::SchemaKind::Integration => {
            if schema_path.ends_with("/properties/role")
                || schema_path.ends_with("/properties/type")
                || schema_path.ends_with("/properties/format")
                || schema_path.ends_with("/properties/canonicalization")
                || schema_path.ends_with("/properties/cardinality")
            {
                Some(ApprovedSemanticValue::DeclarationClass)
            } else if schema_path.ends_with("/properties/nullable") {
                Some(ApprovedSemanticValue::Policy)
            } else if [
                "/properties/maxLength",
                "/properties/minLength",
                "/properties/minimum",
                "/properties/maximum",
                "/properties/max_bytes",
                "/properties/calls",
                "/properties/request_bytes",
                "/properties/source_bytes",
                "/properties/deadline",
            ]
            .iter()
            .any(|suffix| schema_path.ends_with(suffix))
            {
                Some(ApprovedSemanticValue::Limit)
            } else {
                None
            }
        }
        knowledge::SchemaKind::Environment => {
            if schema_path.ends_with("/properties/profile")
                || schema_path.ends_with("/properties/algorithm")
                || schema_path.ends_with("/properties/type")
            {
                Some(ApprovedSemanticValue::DeclarationClass)
            } else if schema_path.ends_with("/properties/scopes/items") {
                Some(ApprovedSemanticValue::HumanIntent)
            } else if schema_path.ends_with("/properties/required") {
                Some(ApprovedSemanticValue::Policy)
            } else if [
                "/properties/per_minute",
                "/properties/burst",
                "/properties/concurrency",
                "/properties/timeout",
                "/properties/worker_memory_bytes",
            ]
            .iter()
            .any(|suffix| schema_path.ends_with(suffix))
            {
                Some(ApprovedSemanticValue::Limit)
            } else {
                None
            }
        }
        knowledge::SchemaKind::Entity => {
            if schema_path.ends_with("/properties/type")
                || schema_path.ends_with("/properties/format")
                || schema_path.ends_with("/properties/additionalProperties")
            {
                Some(ApprovedSemanticValue::DeclarationClass)
            } else if [
                "/properties/minLength",
                "/properties/maxLength",
                "/properties/minimum",
                "/properties/maximum",
                "/properties/max_records",
                "/properties/max_bytes",
                "/properties/refresh",
                "/properties/retain_generations",
            ]
            .iter()
            .any(|suffix| schema_path.ends_with(suffix))
            {
                Some(ApprovedSemanticValue::Limit)
            } else {
                None
            }
        }
        knowledge::SchemaKind::Fixture => None,
    }
}

fn classifier_safe_value(
    knowledge: &knowledge::FieldKnowledge,
    value: Option<ExplanationScalar>,
    approval: Option<ApprovedSemanticValue>,
) -> ClassifierSafeReportedValue {
    let classification = knowledge.sensitivity;
    match knowledge.sensitivity {
        knowledge::Sensitivity::Sensitive => ClassifierSafeReportedValue::Redacted {
            classification,
            reason: RedactionReason::SensitiveMetadata,
        },
        knowledge::Sensitivity::SecretReference | knowledge::Sensitivity::SecretValue => {
            ClassifierSafeReportedValue::Redacted {
                classification,
                reason: RedactionReason::SecretMaterial,
            }
        }
        knowledge::Sensitivity::RedactedFixture => ClassifierSafeReportedValue::Redacted {
            classification,
            reason: RedactionReason::Policy,
        },
        knowledge::Sensitivity::Public => classifier_approved_value(classification, false, value)
            .unwrap_or(ClassifierSafeReportedValue::Absent),
        knowledge::Sensitivity::Internal | knowledge::Sensitivity::Structural => {
            classifier_approved_value(classification, approval.is_some(), value).unwrap_or(
                ClassifierSafeReportedValue::Redacted {
                    classification,
                    reason: RedactionReason::Policy,
                },
            )
        }
    }
}

fn classifier_approved_value(
    classification: FieldSensitivity,
    semantic_approved: bool,
    value: Option<ExplanationScalar>,
) -> Option<ClassifierSafeReportedValue> {
    let value = value?;
    ClassifierApprovedJson::after_classification(
        classification,
        semantic_approved,
        value.into_classifier_json(),
    )
    .map(|value| ClassifierSafeReportedValue::Public { value })
}

fn report_schema_kind(kind: knowledge::SchemaKind) -> ProjectAuthoringSchema {
    match kind {
        knowledge::SchemaKind::Project => ProjectAuthoringSchema::Project,
        knowledge::SchemaKind::Environment => ProjectAuthoringSchema::Environment,
        knowledge::SchemaKind::Integration => ProjectAuthoringSchema::Integration,
        knowledge::SchemaKind::Fixture => ProjectAuthoringSchema::Fixture,
        knowledge::SchemaKind::Entity => ProjectAuthoringSchema::Entity,
    }
}

fn report_field_knowledge(knowledge: &knowledge::FieldKnowledge) -> ProjectFieldKnowledge {
    ProjectFieldKnowledge {
        path_kind: knowledge.path_kind,
        semantic_owner: knowledge.semantic_owner,
        human_owner: knowledge.human_owner,
        sensitivity: knowledge.sensitivity,
        products: knowledge.products.clone(),
        introduced_in: knowledge.introduced_in.clone(),
        availability: knowledge.availability,
        stability: knowledge.stability,
        migration: knowledge.migration,
        consumers: knowledge.consumers.clone(),
        generated_artifacts: knowledge.generated_artifacts.clone(),
        review_classes: knowledge.review_classes.clone(),
        semantic_rules: knowledge.semantic_rules.clone(),
    }
}

fn knowledge_semantic_rule_id(rule: knowledge::SemanticRule) -> &'static str {
    match rule {
        knowledge::SemanticRule::KnowledgeOnly => "knowledge_only",
        knowledge::SemanticRule::GeneratedDocsNeverLoadCountryValues => {
            "generated_docs_never_load_country_values"
        }
        knowledge::SemanticRule::SecretNeverReportable => "secret_never_reportable",
        knowledge::SemanticRule::SyntheticFixtureValueRedacted => {
            "synthetic_fixture_value_redacted"
        }
        knowledge::SemanticRule::SensitiveOperationalMetadata => "sensitive_operational_metadata",
        knowledge::SemanticRule::ArbitraryMapKeysNotFixedProperties => {
            "arbitrary_map_keys_not_fixed_properties"
        }
        knowledge::SemanticRule::ArrayItemsShareElementContract => {
            "array_items_share_element_contract"
        }
        knowledge::SemanticRule::BranchHasNoAuthoredValue => "branch_has_no_authored_value",
    }
}

fn escape_explanation_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod explanation_tests {
    use super::*;

    fn bounded_http_project() -> LoadedRegistryProject {
        load_registry_project(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http"),
            Some("local"),
        )
        .expect("bounded HTTP starter loads")
    }

    fn integration_field<'a>(
        report: &'a ProjectExplanationReportV1,
        integration: &str,
        path: &str,
    ) -> &'a ProjectFieldExplanation {
        report
            .fields
            .iter()
            .find(|field| {
                matches!(
                    &field.address,
                    ProjectFieldAddress::Integration {
                        integration: actual,
                        path: actual_path,
                    } if actual == integration && actual_path.as_str() == path
                )
            })
            .expect("integration explanation field exists")
    }

    fn project_public_text<'a>(report: &'a ProjectExplanationReportV1, path: &str) -> &'a str {
        let field = report
            .fields
            .iter()
            .find(|field| {
                matches!(
                    &field.address,
                    ProjectFieldAddress::Project { path: actual_path }
                        if actual_path.as_str() == path
                )
            })
            .expect("project explanation field exists");
        let ClassifierSafeReportedValue::Public { value } = &field.reported_value else {
            panic!("classifier-approved project classification is public");
        };
        value
            .as_value()
            .as_str()
            .expect("project classification is text")
    }

    #[test]
    fn trusted_local_terminal_rendering_fails_closed_for_prohibited_internal_states() {
        const SENTINEL: &str = "TRUSTED_LOCAL_PROHIBITED_SENTINEL";
        let address = ProjectFieldAddress::Project {
            path: JsonPointer::new("/registry/id".to_owned()).expect("pointer is valid"),
        };
        let derived = ProjectTrustedLocalAuthoredValue {
            address: address.clone(),
            source: FieldSourceKind::Derived,
            sensitivity: FieldSensitivity::Internal,
            value: json!(SENTINEL),
        };
        let secret = ProjectTrustedLocalAuthoredValue {
            address: address.clone(),
            source: FieldSourceKind::Authored,
            sensitivity: FieldSensitivity::SecretReference,
            value: json!(SENTINEL),
        };
        let fixture = ProjectTrustedLocalAuthoredValue {
            address: ProjectFieldAddress::Fixture {
                integration: "person-record".to_owned(),
                fixture: "private".to_owned(),
                path: JsonPointer::new("/input/person_id".to_owned()).expect("pointer is valid"),
            },
            source: FieldSourceKind::Authored,
            sensitivity: FieldSensitivity::Internal,
            value: json!(SENTINEL),
        };
        let parser = ProjectTrustedLocalAuthoredValue {
            address: ProjectFieldAddress::Project {
                path: JsonPointer::new("/services/example/claims/example/cel".to_owned())
                    .expect("pointer is valid"),
            },
            source: FieldSourceKind::Authored,
            sensitivity: FieldSensitivity::Internal,
            value: json!(SENTINEL),
        };

        for (field, expected) in [
            (
                derived,
                "only authored values can enter trusted-local authored output",
            ),
            (
                secret,
                "secret or fixture data cannot enter trusted-local authored output",
            ),
            (
                fixture,
                "fixture data cannot enter trusted-local authored output",
            ),
            (
                parser,
                "secret locator or parser input cannot enter trusted-local authored output",
            ),
        ] {
            let error = field
                .terminal_line()
                .expect_err("prohibited internal state fails closed");
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains(SENTINEL));
        }
    }

    #[test]
    fn bounded_http_explanation_reports_effective_defaults_and_knowledge() {
        let loaded = bounded_http_project();
        let report =
            generated_explanation(&loaded, "local").expect("bounded HTTP explanation generates");

        let request_bytes = integration_field(&report, "person-record", "/limits/request_bytes");
        assert_eq!(request_bytes.source.kind, FieldSourceKind::Defaulted);
        assert_eq!(request_bytes.state.presence, FieldPresence::Defaulted);
        assert_eq!(request_bytes.state.effect, FieldEffect::Effective);
        assert!(
            request_bytes
                .default
                .as_ref()
                .expect("compiler default is reported")
                .applied
        );
        let ClassifierSafeReportedValue::Public { value } = &request_bytes.reported_value else {
            panic!("classifier-approved effective bound is public");
        };
        assert_eq!(value.as_value(), &json!(64 * 1024));
        assert_eq!(
            request_bytes.knowledge.semantic_owner,
            FieldSemanticOwner::IntegrationContract
        );
        assert!(request_bytes
            .knowledge
            .generated_artifacts
            .contains(&FieldGeneratedArtifact::RelayConfig));
        assert!(request_bytes
            .knowledge
            .generated_artifacts
            .contains(&FieldGeneratedArtifact::NotaryConfig));

        let calls = integration_field(&report, "person-record", "/limits/calls");
        assert_eq!(calls.source.kind, FieldSourceKind::Derived);
        assert_eq!(
            calls.source.semantic_rule_id.as_deref(),
            Some("compiler.http_single_call")
        );
        assert_eq!(
            calls
                .default
                .as_ref()
                .expect("intrinsic default is reported")
                .source,
            FieldDefaultSource::SemanticRule
        );
        let response_format =
            integration_field(&report, "person-record", "/source/response/format");
        assert_eq!(response_format.source.kind, FieldSourceKind::Defaulted);
        let ClassifierSafeReportedValue::Public { value } = &response_format.reported_value else {
            panic!("classifier-approved response format is public");
        };
        assert_eq!(value.as_value(), &json!("json"));

        let purpose = report
            .fields
            .iter()
            .find(|field| {
                matches!(
                    &field.address,
                    ProjectFieldAddress::Project { path }
                        if path.as_str() == "/services/person-verification/purpose"
                )
            })
            .expect("service purpose explanation exists");
        assert_eq!(purpose.source.kind, FieldSourceKind::Authored);
        assert_eq!(purpose.state.presence, FieldPresence::Authored);
        assert_eq!(
            purpose.knowledge.semantic_owner,
            FieldSemanticOwner::AuthoringContract
        );
        assert!(purpose
            .knowledge
            .consumers
            .contains(&FieldKnowledgeConsumer::RegistryNotary));
        let ClassifierSafeReportedValue::Public { value } = &purpose.reported_value else {
            panic!("classifier-approved human intent is public");
        };
        assert_eq!(
            value.as_value(),
            &json!("public-service-person-verification")
        );
        assert_eq!(
            project_public_text(
                &report,
                "/services/person-verification/claims/person-active/evidence"
            ),
            "registry_backed"
        );
        assert_eq!(
            project_public_text(
                &report,
                "/services/person-verification/claims/person-record-exists/evidence"
            ),
            "registry_backed"
        );
        let issuance_algorithm = report
            .fields
            .iter()
            .find(|field| {
                matches!(
                    &field.address,
                    ProjectFieldAddress::Environment { path, .. }
                        if path.as_str() == "/issuance/algorithm"
                )
            })
            .expect("effective issuance algorithm exists");
        assert_eq!(issuance_algorithm.source.kind, FieldSourceKind::Defaulted);
        assert!(issuance_algorithm
            .default
            .as_ref()
            .is_some_and(|default| default.applied));

        let serialized_once = serde_json::to_vec(&report).expect("report serializes");
        let serialized_twice = serde_json::to_vec(
            &generated_explanation(&loaded, "local")
                .expect("second bounded HTTP explanation generates"),
        )
        .expect("second report serializes");
        assert_eq!(serialized_once, serialized_twice);
    }

    #[test]
    fn source_free_cel_explanation_remains_self_attested() {
        let loaded = load_registry_project(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring/notary-only-evaluation"),
            Some("local"),
        )
        .expect("source-free Notary project loads");
        let report =
            generated_explanation(&loaded, "local").expect("source-free explanation generates");

        assert_eq!(
            project_public_text(
                &report,
                "/services/applicant-evaluation/claims/application-complete/evidence"
            ),
            "self_attested"
        );
    }

    #[test]
    fn explanation_never_serializes_sensitive_or_request_fixture_sentinels() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_embedded_dir(
            ProjectStarter::Http
                .embedded()
                .expect("HTTP starter is embedded"),
            temporary.path(),
        )
        .expect("HTTP starter copies");
        fs::write(
            temporary.path().join("environments/local.yaml"),
            r#"version: 1
integrations:
  person-record:
    source:
      origin: https://ORIGIN_SENTINEL.invalid
      allowed_private_cidrs: [10.77.0.0/16]
      credential:
        token: { secret: SECRET_REFERENCE_SENTINEL }
        generation: 77
issuance:
  issuer: did:web:ISSUER_SENTINEL.invalid
  signing_kid: SIGNING_ID_SENTINEL
  signing_key: { secret: SIGNING_SECRET_SENTINEL }
  generation: 88
callers:
  evidence-client:
    api_key_fingerprint: { secret: CALLER_SECRET_SENTINEL }
    scopes: ["evidence:person:read"]
relay:
  origin: https://RELAY_ORIGIN_SENTINEL.invalid
  issuer: https://ENDPOINT_SENTINEL.invalid
  jwks_url: https://ENDPOINT_SENTINEL.invalid/JWKS_PATH_SENTINEL
  audience: CLIENT_ID_SENTINEL
  allowed_clients: [CLIENT_ID_SENTINEL]
notary_relay:
  base_url: http://127.0.0.1:8080
  workload_client_id: CLIENT_ID_SENTINEL
  token_file: /ABSOLUTE/RUNTIME/FILE/PATH_SENTINEL
deployment:
  profile: local
  relay: { service: fictional-registry-relay }
  notary: { service: fictional-registry-notary }
"#,
        )
        .expect("sentinel environment writes");
        fs::write(
            temporary
                .path()
                .join("integrations/person-record/integration.yaml"),
            r#"version: 1
id: person-record
revision: 1
source:
  product: replace-with-source-product
  versions: { unverified: [replace-with-source-version] }
  auth: { type: static_bearer }
input:
  person_id:
    role: selector
    type: string
    maxLength: 64
capability:
  http:
    request:
      method: POST
      semantics: read_only
      path: /REQUEST/PATH/SENTINEL/{input.person_id}
      query: { QUERY_SENTINEL: QUERY_VALUE_SENTINEL }
      headers: { X-Projection: HEADER_VALUE_SENTINEL }
      body: { REQUEST_BODY_SENTINEL: REQUEST_PAYLOAD_SENTINEL }
    response:
      no_match: [404]
      ambiguous: [409]
outputs:
  active:
    type: boolean
    x-registry-source: /SOURCE_VALUE_SENTINEL
not_applicable:
  subject_mismatch:
    rationale: The selected response projection contains no identifier that can be compared with the requested person identifier.
    request_fixture: active-person
"#,
        )
        .expect("sentinel integration writes");
        fs::write(
            temporary
                .path()
                .join("integrations/person-record/fixtures/active.yaml"),
            r#"name: active-person
classification: synthetic
input: { person_id: FIXTURE_INPUT_SENTINEL }
interactions:
  - expect:
      method: POST
      path: /REQUEST/PATH/SENTINEL/FIXTURE
      query: { QUERY_SENTINEL: QUERY_VALUE_SENTINEL }
      headers: { X-Projection: HEADER_VALUE_SENTINEL }
      body: { REQUEST_BODY_SENTINEL: REQUEST_PAYLOAD_SENTINEL }
    respond: { status: 200, body: { FIXTURE_BODY_SENTINEL: true } }
expect:
  outcome: match
  outputs: { active: true }
  claims: { person-record-exists: true, person-active: true }
"#,
        )
        .expect("sentinel fixture writes");
        let project_path = temporary.path().join(PROJECT_FILE);
        let project = fs::read_to_string(&project_path).expect("project reads");
        fs::write(
            &project_path,
            project.replace(
                "cel: person_record.matched",
                "cel: 'person_record.matched && \"CEL_SENTINEL\" == \"CEL_SENTINEL\"'",
            ),
        )
        .expect("sentinel project writes");

        let loaded =
            load_registry_project(temporary.path(), Some("local")).expect("sentinel project loads");
        let report =
            generated_explanation(&loaded, "local").expect("sentinel explanation generates");
        let serialized = serde_json::to_string(&report).expect("sentinel report serializes");
        for sentinel in [
            "ORIGIN_SENTINEL",
            "10.77.0.0/16",
            "SECRET_REFERENCE_SENTINEL",
            "SIGNING_SECRET_SENTINEL",
            "CALLER_SECRET_SENTINEL",
            "SIGNING_ID_SENTINEL",
            "ENDPOINT_SENTINEL",
            "JWKS_PATH_SENTINEL",
            "CLIENT_ID_SENTINEL",
            "/ABSOLUTE/RUNTIME/FILE/PATH_SENTINEL",
            "REQUEST/PATH/SENTINEL",
            "QUERY_SENTINEL",
            "QUERY_VALUE_SENTINEL",
            "HEADER_VALUE_SENTINEL",
            "REQUEST_BODY_SENTINEL",
            "REQUEST_PAYLOAD_SENTINEL",
            "SOURCE_VALUE_SENTINEL",
            "FIXTURE_INPUT_SENTINEL",
            "FIXTURE_BODY_SENTINEL",
            "CEL_SENTINEL",
        ] {
            assert!(
                !serialized.contains(sentinel),
                "classifier-safe report leaked {sentinel}"
            );
        }
        assert!(report.fields.iter().any(|field| {
            matches!(
                field.reported_value,
                ClassifierSafeReportedValue::Redacted {
                    classification: FieldSensitivity::SecretReference,
                    reason: RedactionReason::SecretMaterial,
                }
            )
        }));
        assert!(report.fields.iter().any(|field| {
            matches!(
                field.reported_value,
                ClassifierSafeReportedValue::Redacted {
                    classification: FieldSensitivity::RedactedFixture,
                    ..
                }
            )
        }));

        let trusted = trusted_local_authored_values(&loaded, &report)
            .expect("trusted-local authored values are selected");
        assert!(trusted.iter().all(|field| {
            matches!(
                field.source,
                FieldSourceKind::Authored | FieldSourceKind::EnvironmentBound
            ) && matches!(
                field.sensitivity,
                FieldSensitivity::Public
                    | FieldSensitivity::Internal
                    | FieldSensitivity::Structural
                    | FieldSensitivity::Sensitive
            ) && !matches!(field.address, ProjectFieldAddress::Fixture { .. })
        }));
        let trusted_values = trusted
            .iter()
            .map(|field| serde_json::to_string(&field.value).expect("scalar serializes"))
            .collect::<Vec<_>>()
            .join("\n");
        for visible in ["ORIGIN_SENTINEL", "ISSUER_SENTINEL"] {
            assert!(
                trusted_values.contains(visible),
                "trusted-local review should expose authored non-secret metadata {visible}"
            );
        }
        for hidden in [
            "SECRET_REFERENCE_SENTINEL",
            "SIGNING_SECRET_SENTINEL",
            "CALLER_SECRET_SENTINEL",
            "FIXTURE_INPUT_SENTINEL",
            "FIXTURE_BODY_SENTINEL",
            "/ABSOLUTE/RUNTIME/FILE/PATH_SENTINEL",
            "REQUEST_PAYLOAD_SENTINEL",
            "SOURCE_VALUE_SENTINEL",
            "CEL_SENTINEL",
        ] {
            assert!(
                !trusted_values.contains(hidden),
                "trusted-local review leaked prohibited value {hidden}"
            );
        }
    }

    #[test]
    fn records_standard_objects_use_typed_leaf_knowledge_without_leaking_values() {
        let schemas = explanation_schema_set().expect("published explanation schemas load");
        let mut builder = ExplanationBuilder::new(&schemas);
        let project = json!({
            "version": 1,
            "registry": { "id": "records-standards-test" },
            "services": {
                "people-records": {
                    "kind": "records_api",
                    "entity": "people",
                    "api": {
                        "scopes": {
                            "metadata": "records:metadata",
                            "rows": "records:rows"
                        },
                        "projection": ["person_id"],
                        "pagination": {
                            "default_limit": 10,
                            "max_limit": 100
                        },
                        "standards": {
                            "ogc_features": {
                                "collection_id": "COLLECTION_ID_SENTINEL",
                                "geometry": {
                                    "kind": "point",
                                    "longitude_field": "longitude",
                                    "latitude_field": "latitude",
                                    "crs": "CRS_SENTINEL"
                                }
                            },
                            "sp_dci": {
                                "registry": "SP_DCI_REGISTRY_SENTINEL",
                                "registry_type": "civil-registry",
                                "record_type": "person",
                                "identifiers": { "person_id": "person_id" },
                                "expression_fields": {}
                            }
                        }
                    }
                }
            }
        });
        builder
            .add_authored_document(
                knowledge::SchemaKind::Project,
                ExplanationAddressScope::Project,
                &project,
                ExplanationSource::Authored,
            )
            .expect("records standards explanation generates");
        let fields = builder.finish();
        for path in [
            "/services/people-records/api/standards/ogc_features/collection_id",
            "/services/people-records/api/standards/ogc_features/geometry/crs",
            "/services/people-records/api/standards/sp_dci/registry",
        ] {
            let field = fields
                .iter()
                .find(|field| {
                    matches!(
                        &field.address,
                        ProjectFieldAddress::Project { path: field_path }
                            if field_path.as_str() == path
                    )
                })
                .unwrap_or_else(|| panic!("typed standards field {path} is represented"));
            assert!(matches!(
                field.reported_value,
                ClassifierSafeReportedValue::Redacted {
                    classification: FieldSensitivity::Internal,
                    reason: RedactionReason::Policy,
                }
            ));
        }
        let serialized = serde_json::to_string(&fields).expect("standards fields serialize");
        for sentinel in [
            "COLLECTION_ID_SENTINEL",
            "CRS_SENTINEL",
            "SP_DCI_REGISTRY_SENTINEL",
        ] {
            assert!(
                !serialized.contains(sentinel),
                "typed standards explanation leaked {sentinel}"
            );
        }
    }

    #[test]
    fn explanation_rejects_authored_bytes_changed_after_load() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        copy_embedded_dir(
            ProjectStarter::Http
                .embedded()
                .expect("HTTP starter is embedded"),
            temporary.path(),
        )
        .expect("HTTP starter copies");
        let loaded =
            load_registry_project(temporary.path(), Some("local")).expect("HTTP starter loads");
        let project_path = temporary.path().join(PROJECT_FILE);
        let project = fs::read_to_string(&project_path).expect("project reads");
        fs::write(
            project_path,
            project.replace("public-service-person-verification", "changed-after-load"),
        )
        .expect("project changes after load");

        let error = generated_explanation(&loaded, "local")
            .expect_err("explanation must reject a TOCTOU input change");
        assert_eq!(
            error.to_string(),
            "authored explanation input changed after the project was loaded"
        );
    }
}
