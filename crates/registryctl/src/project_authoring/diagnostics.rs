// SPDX-License-Identifier: Apache-2.0

const MAX_AUTHORING_DIAGNOSTICS: usize = 64;
const MAX_ENVIRONMENT_DIRECTORY_ENTRIES: usize = 128;
const FIXTURE_BODY_BYTES: u64 = 8 * 1024 * 1024;
const FIXTURE_BODY_CLOSURE_BYTES: u64 = 16 * 1024 * 1024;
type DiagnosticResult<T> = std::result::Result<T, Box<ProjectAuthoringDiagnostic>>;

enum DiagnosticReadFailure {
    Missing(Box<ProjectAuthoringDiagnostic>),
    Terminal(Box<ProjectAuthoringDiagnostic>),
}

impl DiagnosticReadFailure {
    fn into_diagnostic(self) -> Box<ProjectAuthoringDiagnostic> {
        match self {
            Self::Missing(diagnostic) | Self::Terminal(diagnostic) => diagnostic,
        }
    }
}

const PROJECT_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind project > project.schema.json";
const ENTITY_SCHEMA_HINT: &str = "registryctl authoring schema --kind entity > entity.schema.json";
const INTEGRATION_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind integration > integration.schema.json";
const FIXTURE_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind fixture > fixture.schema.json";
const ENVIRONMENT_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind environment > environment.schema.json";

#[allow(dead_code)]
const PROJECT_DIAGNOSTIC_CATALOG_SCHEMA_VERSION: &str =
    "registryctl.project_authoring_diagnostic_catalog.v1";

/// A stable, generated-reference definition for an authoring failure code.
///
/// The diagnostic collector may attach a more precise field-specific cause and
/// remediation, but the code's validation contract, safe summary boundary,
/// and documentation route live only here. This prevents emitted codes and
/// the public reference from drifting independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectAuthoringDiagnosticDefinition {
    pub code: &'static str,
    pub phase: &'static str,
    pub rule: &'static str,
    pub accepted: &'static str,
    pub safe_remediation: &'static str,
    pub safe_summary_policy: &'static str,
    pub documentation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed_behavior: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ProjectAuthoringDiagnosticCatalogV1 {
    pub schema_version: &'static str,
    pub diagnostics: Vec<ProjectAuthoringDiagnosticDefinition>,
}

macro_rules! diagnostic_definition {
    ($code:literal, $phase:literal, $rule:literal, $accepted:literal, $remediation:literal, $summary:literal, $route:literal) => {
        ProjectAuthoringDiagnosticDefinition {
            code: $code,
            phase: $phase,
            rule: $rule,
            accepted: $accepted,
            safe_remediation: $remediation,
            safe_summary_policy: $summary,
            documentation: concat!(
                "/reference/diagnostics/authoring/#registryctl--",
                $code
            ),
            replacement: None,
            changed_behavior: None,
        }
    };
}

const AUTHORING_DIAGNOSTIC_CATALOG: &[ProjectAuthoringDiagnosticDefinition] = &[
    diagnostic_definition!("registryctl.authoring.diagnostics.truncated", "aggregation", "diagnostic_limit", "At most 64 diagnostics are returned in deterministic order.", "Fix the reported diagnostics and run the check again.", "no_received_value", "diagnostics-truncated"),
    diagnostic_definition!("registryctl.authoring.entity.invalid", "semantic_validation", "entity_contract", "A declared entity id and shape must match the project contract.", "Correct the entity declaration with the entity schema and its project alias.", "no_received_value", "entity-invalid"),
    diagnostic_definition!("registryctl.authoring.environment.invalid", "semantic_validation", "environment_binding", "Environment bindings must match declared products, integrations, identities, origins, and bounded generations.", "Align the selected environment with the declared project contract.", "no_received_value", "environment-invalid"),
    diagnostic_definition!("registryctl.authoring.file.too_large", "safe_input", "authored_file_size", "Authored files must remain below their documented fixed byte bound.", "Reduce the file below its documented maximum size.", "no_received_value", "file-too-large"),
    diagnostic_definition!("registryctl.authoring.file.unreadable", "safe_input", "authored_file_readability", "A regular file inside the project root must be readable.", "Restore a readable regular project-relative file.", "no_received_value", "file-unreadable"),
    diagnostic_definition!("registryctl.authoring.fixture.invalid", "semantic_validation", "fixture_contract", "Fixtures must be deterministic, bounded, and satisfy the integration contract without live values.", "Correct the fixture declaration and its closed interaction contract.", "no_received_value", "fixture-invalid"),
    diagnostic_definition!("registryctl.authoring.fixture.reserved_body_field", "syntax", "fixture_body_file_reference", "A fixture body object may use `file` only as the closed body-file reference shape.", "Use the documented body-file reference shape or an inline JSON body.", "received_type_only", "fixture-reserved-body-field"),
    diagnostic_definition!("registryctl.authoring.integration.invalid", "semantic_validation", "integration_contract", "An integration alias, capability, and declared contract must be internally consistent.", "Correct the integration declaration with the integration schema.", "no_received_value", "integration-invalid"),
    diagnostic_definition!("registryctl.authoring.path.unsafe", "safe_input", "project_relative_path", "Paths must be normalized project-relative paths to regular non-symlink entries.", "Use a normalized project-relative regular file path.", "no_received_value", "path-unsafe"),
    diagnostic_definition!("registryctl.authoring.project.invalid", "semantic_validation", "project_contract", "Project services, entities, integrations, and references must form a closed valid graph.", "Align the project declaration and referenced contracts.", "no_received_value", "project-invalid"),
    diagnostic_definition!("registryctl.authoring.project.scope_collision", "semantic_validation", "authorization_scope_uniqueness", "Effective authorization scopes must be distinct across records API and attribute-release access.", "Assign distinct scopes to each authorization purpose.", "no_received_value", "project-scope-collision"),
    diagnostic_definition!("registryctl.authoring.script.closed_contract_violation", "script_validation", "released_script_contract", "Scripts must use the released bounded Script contract and module rules.", "Use only the released bounded Script contract.", "no_received_value", "script-closed-contract-violation"),
    diagnostic_definition!("registryctl.authoring.script.invalid_signature", "script_validation", "script_entrypoint_signature", "The Script entrypoint must be exactly `consult(context)`.", "Define the exact released entrypoint signature.", "no_received_value", "script-invalid-signature"),
    diagnostic_definition!("registryctl.authoring.script.syntax_error", "script_validation", "script_syntax", "The Script source must parse under the released runtime.", "Correct the Script syntax at the reported location.", "no_received_value", "script-syntax-error"),
    diagnostic_definition!("registryctl.authoring.script.unknown_function", "script_validation", "script_entrypoint", "The Script must define the released `consult(context)` entrypoint.", "Define consult(context) as the Script entrypoint.", "no_received_value", "script-unknown-function"),
    diagnostic_definition!("registryctl.authoring.yaml.invalid_syntax", "syntax", "closed_yaml_document", "YAML must parse as the selected closed authoring document shape.", "Correct the YAML with the matching authoring schema.", "received_type_only", "yaml-invalid-syntax"),
    ProjectAuthoringDiagnosticDefinition {
        code: "registryctl.authoring.yaml.unknown_field",
        phase: "syntax",
        rule: "closed_yaml_unknown_field",
        accepted: "Only documented fields in the closed authoring schema are accepted.",
        safe_remediation: "Remove the unsupported field or replace it with its documented field.",
        safe_summary_policy: "received_type_only",
        documentation: "/reference/diagnostics/authoring/#registryctl--registryctl.authoring.yaml.unknown_field",
        replacement: Some("No deprecated replacement is implied by an unknown field; use only a documented field."),
        changed_behavior: Some("Unknown fields are rejected rather than ignored."),
    },
];

#[must_use]
#[allow(dead_code)]
pub fn project_authoring_diagnostic_catalog() -> ProjectAuthoringDiagnosticCatalogV1 {
    ProjectAuthoringDiagnosticCatalogV1 {
        schema_version: PROJECT_DIAGNOSTIC_CATALOG_SCHEMA_VERSION,
        diagnostics: AUTHORING_DIAGNOSTIC_CATALOG.to_vec(),
    }
}

pub(crate) fn project_authoring_diagnostic_definitions(
) -> &'static [ProjectAuthoringDiagnosticDefinition] {
    AUTHORING_DIAGNOSTIC_CATALOG
}

fn diagnostic_definition(code: &str) -> &'static ProjectAuthoringDiagnosticDefinition {
    AUTHORING_DIAGNOSTIC_CATALOG
        .iter()
        .find(|definition| definition.code == code)
        .unwrap_or_else(|| panic!("unregistered registryctl authoring diagnostic code: {code}"))
}

impl std::fmt::Display for ProjectAuthoringDiagnostics {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&render_project_authoring_diagnostics(self))
    }
}

impl std::error::Error for ProjectAuthoringDiagnostics {}

#[must_use]
pub fn render_project_authoring_diagnostics(report: &ProjectAuthoringDiagnostics) -> String {
    use std::fmt::Write as _;

    let mut output = format!(
        "Registry Stack project is invalid: {} authoring diagnostic{}",
        report.diagnostics.len(),
        if report.diagnostics.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    for diagnostic in &report.diagnostics {
        let _ = write!(output, "\n{}", diagnostic.file);
        if let Some(line) = diagnostic.line {
            let _ = write!(output, ":{line}");
            if let Some(column) = diagnostic.column {
                let _ = write!(output, ":{column}");
            }
        }
        let _ = write!(output, " [{}] {}", diagnostic.code, diagnostic.cause);
        if let Some(field) = diagnostic.field {
            let _ = write!(output, " (field: {field})");
        }
        if let Some(schema_hint) = diagnostic.schema_hint {
            let _ = write!(output, "\n  Schema: {schema_hint}");
        }
        if let Some(suggestion) = diagnostic.suggestion {
            let _ = write!(output, "\n  Expected: {suggestion}");
        }
        let _ = write!(output, "\n  Fix: {}", diagnostic.remediation);
    }
    output
}

/// Produces the value-free strict JSON fallback for a `check` failure that did
/// not already carry exact typed authoring diagnostics.
///
/// Human output retains the underlying local error. Portable output cannot
/// serialize arbitrary `anyhow` chains because they may contain paths,
/// authored values, or runtime details.
#[must_use]
pub fn redacted_project_check_failure_diagnostics() -> ProjectAuthoringDiagnostics {
    finalized_diagnostics(vec![invalid_diagnostic(
        "registryctl.authoring.project.invalid",
        PROJECT_FILE,
        None,
        "The offline project check could not complete safely.",
        "Correct the reported project or option issue, then run the check again with trusted local human output if more detail is needed.",
        Some(PROJECT_SCHEMA_HINT),
    )])
}

fn collect_project_authoring_diagnostics(
    project_directory: &Path,
    environment_name: &str,
) -> ProjectAuthoringDiagnostics {
    let mut diagnostics = Vec::new();
    let root = match diagnostic_project_root(project_directory) {
        Ok(root) => root,
        Err(diagnostic) => return finalized_diagnostics(vec![*diagnostic]),
    };
    let (_, project_bytes) = match diagnostic_read_relative(
        &root,
        Path::new(PROJECT_FILE),
        None,
        MAX_AUTHORED_FILE_BYTES,
    ) {
        Ok(file) => file,
        Err(diagnostic) => return finalized_diagnostics(vec![*diagnostic]),
    };
    let project: RegistryProject =
        match diagnostic_parse_yaml(&project_bytes, PROJECT_FILE, "project", PROJECT_SCHEMA_HINT) {
            Ok(project) => project,
            Err(diagnostic) => {
                diagnostics.push(*diagnostic);
                collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
                return finalized_diagnostics(diagnostics);
            }
        };
    diagnostics.extend(project_declaration_semantic_diagnostics(&project));
    if !diagnostics.is_empty() {
        collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
        return finalized_diagnostics(diagnostics);
    }

    for reference in project
        .entities
        .values()
        .map(|reference| (&reference.file, "entities.file"))
        .chain(
            project
                .integrations
                .values()
                .map(|reference| (&reference.file, "integrations.file")),
        )
    {
        if validate_relative_authored_path(reference.0).is_err() {
            diagnostics.push(path_unsafe(PROJECT_FILE, Some(reference.1)));
            return finalized_diagnostics(diagnostics);
        }
    }
    if validate_project_shape(&project).is_err() {
        diagnostics.push(invalid_diagnostic(
            "registryctl.authoring.project.invalid",
            PROJECT_FILE,
            None,
            "The project declaration is invalid.",
            "Correct the project declaration before checking referenced files.",
            Some(PROJECT_SCHEMA_HINT),
        ));
        collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
        return finalized_diagnostics(diagnostics);
    }
    if let Err(diagnostic) = inspect_environment_file_boundaries(&root) {
        return finalized_diagnostics(vec![*diagnostic]);
    }

    let mut entities = BTreeMap::new();
    for (alias, reference) in &project.entities {
        let (path, bytes) = match diagnostic_read_relative_classified(
            &root,
            &reference.file,
            Some("entities.file"),
            MAX_AUTHORED_FILE_BYTES,
        ) {
            Ok(file) => file,
            Err(DiagnosticReadFailure::Missing(diagnostic)) => {
                diagnostics.push(*diagnostic);
                continue;
            }
            Err(DiagnosticReadFailure::Terminal(diagnostic)) => {
                diagnostics.push(*diagnostic);
                return finalized_diagnostics(diagnostics);
            }
        };
        let file = normalized_authored_file(&root, &path);
        let document: EntityDefinition =
            match diagnostic_parse_yaml(&bytes, &file, "entity", ENTITY_SCHEMA_HINT) {
                Ok(document) => document,
                Err(diagnostic) => {
                    diagnostics.push(*diagnostic);
                    continue;
                }
            };
        if validate_entity_definition(&document).is_err() || alias != &document.id {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.entity.invalid",
                &file,
                None,
                "The entity declaration is invalid.",
                "Correct the entity declaration and keep its id aligned with the project alias.",
                Some(ENTITY_SCHEMA_HINT),
            ));
            continue;
        }
        if entities
            .insert(document.id.clone(), LoadedEntityDefinition { document })
            .is_some()
        {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.entity.invalid",
                &file,
                Some("id"),
                "An entity is declared more than once.",
                "Declare each entity id once.",
                Some(ENTITY_SCHEMA_HINT),
            ));
        }
    }

    let all_entities_loaded = entities.len() == project.entities.len();
    let mut integrations = BTreeMap::new();
    let mut integration_fixture_complete = BTreeMap::new();
    let mut integration_script_primary = BTreeSet::new();
    for (alias, reference) in &project.integrations {
        let (integration_path, bytes) = match diagnostic_read_relative_classified(
            &root,
            &reference.file,
            Some("integrations.file"),
            MAX_AUTHORED_FILE_BYTES,
        ) {
            Ok(file) => file,
            Err(DiagnosticReadFailure::Missing(diagnostic)) => {
                diagnostics.push(*diagnostic);
                continue;
            }
            Err(DiagnosticReadFailure::Terminal(diagnostic)) => {
                diagnostics.push(*diagnostic);
                return finalized_diagnostics(diagnostics);
            }
        };
        let file = normalized_authored_file(&root, &integration_path);
        let authored: AuthoredIntegrationDocument =
            match diagnostic_parse_yaml(&bytes, &file, "integration", INTEGRATION_SCHEMA_HINT) {
                Ok(document) => document,
                Err(diagnostic) => {
                    diagnostics.push(*diagnostic);
                    continue;
                }
            };
        if let AuthoredCapabilityDeclaration::Snapshot(AuthoredSnapshotCapability { snapshot }) =
            &authored.capability
        {
            if !entities.contains_key(&snapshot.entity) {
                diagnostics.push(cross_file_diagnostic(
                    "registryctl.authoring.project.invalid",
                    &file,
                    Some("capability.snapshot.entity"),
                    "A snapshot integration references an unknown project entity.",
                    "Reference one entity declared by the project.",
                    Some(INTEGRATION_SCHEMA_HINT),
                    vec![
                        diagnostic_address(&file, &["capability", "snapshot", "entity"]),
                        diagnostic_address(PROJECT_FILE, &["entities"]),
                    ],
                ));
                continue;
            }
        }
        let document = match lower_project_integration(&authored, &entities) {
            Ok(document) => document,
            Err(_) => {
                diagnostics.push(invalid_diagnostic(
                    "registryctl.authoring.integration.invalid",
                    &file,
                    None,
                    "The integration declaration is invalid.",
                    "Correct the integration declaration using the authoring schema.",
                    Some(INTEGRATION_SCHEMA_HINT),
                ));
                continue;
            }
        };
        if validate_integration(alias, &document).is_err() {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.integration.invalid",
                &file,
                None,
                "The integration declaration is invalid.",
                "Correct the integration declaration using the authoring schema.",
                Some(INTEGRATION_SCHEMA_HINT),
            ));
            continue;
        }

        let (fixtures, fixtures_complete) = match collect_integration_fixtures(
            &root,
            alias,
            &reference.file,
            &document,
            &mut diagnostics,
        ) {
            Ok(fixtures) => fixtures,
            Err(diagnostic) => {
                diagnostics.push(*diagnostic);
                return finalized_diagnostics(diagnostics);
            }
        };
        let mut loaded = LoadedIntegration {
            document,
            fixtures,
            script: None,
            script_modules: Vec::new(),
        };
        let script_primary = match collect_integration_script(
            &root,
            &integration_path,
            &file,
            &mut loaded,
            &mut diagnostics,
        ) {
            Ok(script_primary) => script_primary,
            Err(diagnostic) => {
                diagnostics.push(*diagnostic);
                return finalized_diagnostics(diagnostics);
            }
        };
        if script_primary {
            integration_script_primary.insert(alias.clone());
        }
        integration_fixture_complete.insert(alias.clone(), fixtures_complete);
        integrations.insert(alias.clone(), loaded);
    }

    let before_environment = diagnostics.len();
    let environment =
        collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
    if diagnostics[before_environment..]
        .iter()
        .any(|diagnostic| terminal_diagnostic_code(diagnostic.code))
    {
        return finalized_diagnostics(diagnostics);
    }
    let all_integrations_loaded = integrations.len() == project.integrations.len();
    if all_entities_loaded && all_integrations_loaded {
        diagnostics.extend(service_integration_link_diagnostics(
            &project,
            &integrations,
        ));
        if validate_project_entity_links(&project, &integrations, &entities).is_err() {
            if let Some(collision) = project_records_scope_collision(&project, &entities) {
                let (field, cause, remediation) = match collision.kind {
                    RecordsScopeCollisionKind::RecordApi => (
                        "services.api.scopes",
                        "Effective records API authorization scopes collide.",
                        "Give metadata, aggregate, row, and evidence-verification access distinct scopes.",
                    ),
                    RecordsScopeCollisionKind::AttributeRelease => (
                        "services.api.attribute_release_profiles.release_scope",
                        "An attribute release scope collides with a records API authorization scope.",
                        "Keep attribute release access distinct from metadata, aggregate, row, and evidence-verification access.",
                    ),
                };
                diagnostics.push(invalid_diagnostic(
                    "registryctl.authoring.project.scope_collision",
                    PROJECT_FILE,
                    Some(field),
                    cause,
                    remediation,
                    Some(PROJECT_SCHEMA_HINT),
                ));
            } else {
                let relationship_diagnostics =
                    project_entity_link_diagnostics(&project, &integrations, &entities);
                if relationship_diagnostics.is_empty() {
                    diagnostics.push(invalid_diagnostic(
                        "registryctl.authoring.project.invalid",
                        PROJECT_FILE,
                        Some("services"),
                        "A project entity reference is inconsistent.",
                        "Align services, snapshots, and relationships with declared entities.",
                        Some(PROJECT_SCHEMA_HINT),
                    ));
                } else {
                    diagnostics.extend(relationship_diagnostics);
                }
            }
        }
        for (alias, integration) in &integrations {
            if integration_fixture_complete.get(alias) == Some(&true)
                && !integration_script_primary.contains(alias)
                && validate_not_applicable(
                    alias,
                    &integration.document,
                    &integration.fixtures,
                    &entities,
                    integration.script.as_ref(),
                    &integration.script_modules,
                )
                .is_err()
            {
                diagnostics.push(not_applicable_diagnostic(
                    &root,
                    &project,
                    alias,
                    integration,
                    &entities,
                ));
            }
        }
        if let Some(environment) = environment.as_ref() {
            collect_environment_semantics(
                &project,
                &integrations,
                &entities,
                environment,
                environment_name,
                &mut diagnostics,
            );
        }
    }
    finalized_diagnostics(diagnostics)
}

fn project_declaration_semantic_diagnostics(
    project: &RegistryProject,
) -> Vec<ProjectAuthoringDiagnostic> {
    let mut diagnostics = Vec::new();
    for (service_id, service) in project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::ConsultationApi)
    {
        for (consultation_id, consultation) in &service.consultations {
            if !project.integrations.contains_key(&consultation.integration) {
                diagnostics.push(cross_file_diagnostic(
                    "registryctl.authoring.project.invalid",
                    PROJECT_FILE,
                    Some("services.consultations.integration"),
                    "A service consultation references an unknown integration.",
                    "Reference one integration declared by the project.",
                    Some(PROJECT_SCHEMA_HINT),
                    vec![
                        diagnostic_address(
                            PROJECT_FILE,
                            &[
                                "services",
                                service_id,
                                "consultations",
                                consultation_id,
                                "integration",
                            ],
                        ),
                        diagnostic_address(PROJECT_FILE, &["integrations"]),
                    ],
                ));
            }
            for (input_id, mapping) in &consultation.input {
                if validate_request_mapping(mapping).is_err() {
                    diagnostics.push(cross_file_diagnostic(
                        "registryctl.authoring.project.invalid",
                        PROJECT_FILE,
                        Some("services.consultations.input"),
                        "A consultation input uses an unsupported governed request path.",
                        "Use request.target.id, request.target.identifiers.<scheme>, or request.target.attributes.<name>.",
                        Some(PROJECT_SCHEMA_HINT),
                        vec![diagnostic_address(
                            PROJECT_FILE,
                            &[
                                "services",
                                service_id,
                                "consultations",
                                consultation_id,
                                "input",
                                input_id,
                            ],
                        )],
                    ));
                }
            }
        }

    }
    diagnostics
}

fn collect_selected_environment_syntax(
    root: &Path,
    name: &str,
    diagnostics: &mut Vec<ProjectAuthoringDiagnostic>,
) -> Option<EnvironmentDocument> {
    if validate_stable_id(name, "environment").is_err() {
        diagnostics.push(path_unsafe(PROJECT_FILE, Some("environment")));
        return None;
    }
    let relative = PathBuf::from("environments").join(format!("{name}.yaml"));
    let (_, bytes) = match diagnostic_read_relative(
        root,
        &relative,
        Some("environment"),
        MAX_AUTHORED_FILE_BYTES,
    ) {
        Ok(file) => file,
        Err(diagnostic) => {
            diagnostics.push(*diagnostic);
            return None;
        }
    };
    let file = relative_path_string(&relative).unwrap_or_else(|| "environments".to_string());
    match diagnostic_parse_yaml(&bytes, &file, "environment", ENVIRONMENT_SCHEMA_HINT) {
        Ok(environment) => Some(environment),
        Err(diagnostic) => {
            diagnostics.push(*diagnostic);
            None
        }
    }
}

fn collect_integration_fixtures(
    root: &Path,
    alias: &str,
    integration_file: &Path,
    document: &IntegrationDocument,
    diagnostics: &mut Vec<ProjectAuthoringDiagnostic>,
) -> DiagnosticResult<(Vec<(PathBuf, FixtureDocument)>, bool)> {
    let Some(parent) = integration_file.parent() else {
        return Err(Box::new(path_unsafe(
            PROJECT_FILE,
            Some("integrations.file"),
        )));
    };
    let directory = parent.join(&document.fixtures);
    let directory_path = diagnostic_directory(root, &directory, Some("fixtures"))?;
    let mut fixture_paths = Vec::new();
    let entries = fs::read_dir(&directory_path).map_err(|_| {
        Box::new(file_unreadable(
            &relative_or_fallback(root, &directory_path),
            Some("fixtures"),
        ))
    })?;
    let mut complete = true;
    for (index, entry) in entries.enumerate() {
        if index > MAX_FIXTURES {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &relative_or_fallback(root, &directory_path),
                Some("fixtures"),
                "The fixture directory exceeds its fixed entry bound.",
                "Reduce the fixture directory to 128 YAML files and one optional bodies directory.",
                Some(FIXTURE_SCHEMA_HINT),
            ));
            complete = false;
            break;
        }
        let entry = entry.map_err(|_| {
            Box::new(file_unreadable(
                &relative_or_fallback(root, &directory_path),
                Some("fixtures"),
            ))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            Box::new(file_unreadable(
                &relative_or_fallback(root, &path),
                Some("fixtures"),
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Box::new(path_unsafe(
                &relative_or_fallback(root, &directory_path),
                Some("fixtures"),
            )));
        }
        if metadata.is_dir() {
            if path.file_name().and_then(OsStr::to_str) == Some("bodies") {
                continue;
            }
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &relative_or_fallback(root, &directory_path),
                Some("fixtures"),
                "The fixture directory contains an unsupported entry.",
                "Keep fixture YAML files directly in the fixture directory and bodies under bodies/.",
                Some(FIXTURE_SCHEMA_HINT),
            ));
            complete = false;
            continue;
        }
        if path.extension().and_then(OsStr::to_str) != Some("yaml") {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &relative_or_fallback(root, &directory_path),
                Some("fixtures"),
                "The fixture directory contains an unsupported file.",
                "Keep only YAML fixture declarations and the optional bodies directory.",
                Some(FIXTURE_SCHEMA_HINT),
            ));
            complete = false;
            continue;
        }
        fixture_paths.push(path);
    }
    fixture_paths.sort_by(|left, right| {
        left.as_os_str()
            .as_encoded_bytes()
            .cmp(right.as_os_str().as_encoded_bytes())
    });
    if fixture_paths.is_empty() || fixture_paths.len() > MAX_FIXTURES {
        diagnostics.push(invalid_diagnostic(
            "registryctl.authoring.fixture.invalid",
            &relative_or_fallback(root, &directory_path),
            Some("fixtures"),
            "The integration must contain between one and 128 fixtures.",
            "Add a fixture or reduce the fixture set to the supported bound.",
            Some(FIXTURE_SCHEMA_HINT),
        ));
        complete = false;
    }
    fixture_paths.truncate(MAX_FIXTURES);

    let mut fixtures = Vec::new();
    let mut body_cache = BTreeMap::new();
    let mut body_paths = BTreeSet::new();
    let mut body_closure_bytes = 0_u64;
    for path in fixture_paths {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Box::new(path_unsafe(PROJECT_FILE, Some("fixtures"))))?;
        let (_, bytes) =
            diagnostic_read_relative(root, relative, Some("fixture"), MAX_AUTHORED_FILE_BYTES)?;
        let file = relative_path_string(relative).unwrap_or_else(|| "fixtures".to_string());
        let authored: AuthoredFixtureDocument =
            match diagnostic_parse_yaml(&bytes, &file, "fixture", FIXTURE_SCHEMA_HINT) {
                Ok(document) => document,
                Err(diagnostic) => {
                    diagnostics.push(*diagnostic);
                    complete = false;
                    continue;
                }
            };
        for body in authored_fixture_body_paths(&authored) {
            let Some(body_relative) = diagnostic_fixture_body_relative(relative, body) else {
                return Err(Box::new(path_unsafe(&file, Some("interactions.body"))));
            };
            let (_, body_bytes) = diagnostic_read_relative(
                root,
                &body_relative,
                Some("interactions.body"),
                FIXTURE_BODY_BYTES,
            )?;
            if body_paths.insert(body_relative) {
                body_closure_bytes = body_closure_bytes
                    .saturating_add(u64::try_from(body_bytes.len()).unwrap_or(u64::MAX));
            }
        }
        let fixture = match lower_authored_fixture(
            root,
            &directory_path,
            authored,
            &mut body_cache,
            FIXTURE_BODY_BYTES,
        ) {
            Ok(fixture) => fixture,
            Err(_) => {
                diagnostics.push(invalid_diagnostic(
                    "registryctl.authoring.fixture.invalid",
                    &file,
                    None,
                    "The fixture declaration is invalid.",
                    "Correct the fixture declaration and any referenced strict JSON body.",
                    Some(FIXTURE_SCHEMA_HINT),
                ));
                complete = false;
                continue;
            }
        };
        let mut candidate = vec![(path.clone(), fixture)];
        if validate_fixture_inputs(alias, document, &candidate).is_err() {
            diagnostics.push(cross_file_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &file,
                Some("input"),
                "The fixture does not satisfy its integration contract.",
                "Correct fixture inputs, interactions, and expectations without using live values.",
                Some(FIXTURE_SCHEMA_HINT),
                vec![
                    diagnostic_address(&file, &["input"]),
                    diagnostic_address(
                        &relative_path_string(integration_file)
                            .unwrap_or_else(|| PROJECT_FILE.to_string()),
                        &["input"],
                    ),
                ],
            ));
            complete = false;
            continue;
        }
        fixtures.push(candidate.pop().expect("one fixture candidate"));
    }
    if body_closure_bytes > FIXTURE_BODY_CLOSURE_BYTES {
        diagnostics.push(invalid_diagnostic(
            "registryctl.authoring.fixture.invalid",
            &relative_or_fallback(root, &directory_path),
            Some("interactions.body"),
            "The fixture body closure exceeds the 16 MiB bound.",
            "Reduce the total size of referenced fixture bodies.",
            Some(FIXTURE_SCHEMA_HINT),
        ));
        complete = false;
    }
    if validate_fixture_inputs(alias, document, &fixtures).is_err() {
        diagnostics.extend(fixture_set_diagnostics(root, integration_file, &fixtures));
        complete = false;
    }
    fixtures.sort_by(|left, right| left.1.name.as_bytes().cmp(right.1.name.as_bytes()));
    Ok((fixtures, complete))
}

fn service_integration_link_diagnostics(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
) -> Vec<ProjectAuthoringDiagnostic> {
    let mut diagnostics = Vec::new();
    for (service_id, service) in project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::ConsultationApi)
    {
        for (consultation_id, consultation) in &service.consultations {
            let Some(integration) = integrations.get(&consultation.integration) else {
                continue;
            };
            let input_set_mismatch = consultation
                .input
                .keys()
                .ne(integration.document.input.keys());
            let non_injective = consultation.input.values().collect::<BTreeSet<_>>().len()
                != consultation.input.len();
            if input_set_mismatch || non_injective {
                let Some(reference) = project.integrations.get(&consultation.integration) else {
                    continue;
                };
                let integration_file = relative_path_string(&reference.file)
                    .unwrap_or_else(|| PROJECT_FILE.to_string());
                diagnostics.push(cross_file_diagnostic(
                    "registryctl.authoring.project.invalid",
                    PROJECT_FILE,
                    Some("services.consultations"),
                    "A service consultation does not match its integration.",
                    "Align each consultation input with its referenced integration.",
                    Some(PROJECT_SCHEMA_HINT),
                    vec![
                        diagnostic_address(
                            PROJECT_FILE,
                            &[
                                "services",
                                service_id,
                                "consultations",
                                consultation_id,
                                "input",
                            ],
                        ),
                        diagnostic_address(&integration_file, &["input"]),
                    ],
                ));
                continue;
            }
            for (input_id, mapping) in &consultation.input {
                let Some(declaration) = integration.document.input.get(input_id) else {
                    continue;
                };
                let request_source_is_string = mapping == "request.target.id"
                    || mapping.starts_with("request.target.identifiers.");
                if !request_source_is_string
                    || matches!(
                        declaration.input_type,
                        InputType::String | InputType::FullDate
                    )
                {
                    continue;
                }
                let Some(reference) = project.integrations.get(&consultation.integration) else {
                    continue;
                };
                let integration_file = relative_path_string(&reference.file)
                    .unwrap_or_else(|| PROJECT_FILE.to_string());
                diagnostics.push(cross_file_diagnostic(
                    "registryctl.authoring.project.invalid",
                    PROJECT_FILE,
                    Some("services.consultations.input"),
                    "A governed request string source is incompatible with its integration input.",
                    "Map target ids and identifiers only to String or full-date integration inputs; use a target attribute for other scalar types.",
                    Some(PROJECT_SCHEMA_HINT),
                    vec![
                        diagnostic_address(
                            PROJECT_FILE,
                            &[
                                "services",
                                service_id,
                                "consultations",
                                consultation_id,
                                "input",
                                input_id,
                            ],
                        ),
                        diagnostic_address(&integration_file, &["input", input_id, "type"]),
                    ],
                ));
            }
        }
    }
    diagnostics
}

fn project_entity_link_diagnostics(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
) -> Vec<ProjectAuthoringDiagnostic> {
    let mut diagnostics = Vec::new();
    for (service_id, service) in project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::RecordsApi)
    {
        let Some(entity_id) = service.entity.as_deref() else {
            continue;
        };
        let Some(entity) = entities.get(entity_id) else {
            diagnostics.push(cross_file_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services"),
                "A records service references an unknown entity.",
                "Reference one entity declared by the project.",
                Some(PROJECT_SCHEMA_HINT),
                vec![
                    diagnostic_address(PROJECT_FILE, &["services", service_id, "entity"]),
                    diagnostic_address(PROJECT_FILE, &["entities"]),
                ],
            ));
            continue;
        };
        if validate_records_service(service_id, service, &entity.document).is_err() {
            let entity_file = project
                .entities
                .get(entity_id)
                .and_then(|reference| relative_path_string(&reference.file))
                .unwrap_or_else(|| PROJECT_FILE.to_string());
            diagnostics.push(cross_file_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services"),
                "A records service does not match its entity contract.",
                "Align the records projection, filters, relationships, and standards with the entity schema.",
                Some(PROJECT_SCHEMA_HINT),
                vec![
                    diagnostic_address(PROJECT_FILE, &["services", service_id, "api"]),
                    diagnostic_address(&entity_file, &["schema"]),
                ],
            ));
        }
        let Some(api) = service.api.as_ref() else {
            continue;
        };
        for (relationship_id, relationship) in &api.relationships {
            if entities.contains_key(&relationship.target) {
                continue;
            }
            diagnostics.push(cross_file_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services"),
                "A records relationship references an unknown entity.",
                "Point the relationship target at one entity declared by the project.",
                Some(PROJECT_SCHEMA_HINT),
                vec![
                    diagnostic_address(
                        PROJECT_FILE,
                        &[
                            "services",
                            service_id,
                            "api",
                            "relationships",
                            relationship_id,
                            "target",
                        ],
                    ),
                    diagnostic_address(PROJECT_FILE, &["entities"]),
                ],
            ));
        }
    }

    for (integration_id, loaded) in integrations {
        let CapabilityDeclaration::Snapshot { snapshot } = &loaded.document.capability else {
            continue;
        };
        let Some(entity) = entities.get(&snapshot.entity) else {
            continue;
        };
        let invalid_exact = snapshot.exact.iter().any(|(field, input)| {
            !entity.document.schema.properties.contains_key(field)
                || !loaded.document.input.contains_key(input)
        });
        let projected = loaded
            .document
            .outputs
            .values()
            .filter_map(snapshot_output_field)
            .collect::<BTreeSet<_>>();
        let invalid_projection = projected.is_empty()
            || projected
                .iter()
                .any(|field| !entity.document.schema.properties.contains_key(*field));
        let invalid_output_contract = projected.iter().any(|name| {
            let Some(field) = entity.document.schema.properties.get(*name) else {
                return false;
            };
            let Some(output) = loaded.document.outputs.get(*name) else {
                return true;
            };
            match entity_output_contract(name, field) {
                Ok((expected_type, expected_nullable, _)) => {
                    expected_type != output.output_type || expected_nullable != output.nullable
                }
                Err(_) => true,
            }
        });
        if !invalid_exact && !invalid_projection && !invalid_output_contract {
            continue;
        }
        let integration_file = project
            .integrations
            .get(integration_id)
            .and_then(|reference| relative_path_string(&reference.file))
            .unwrap_or_else(|| PROJECT_FILE.to_string());
        let entity_file = project
            .entities
            .get(&snapshot.entity)
            .and_then(|reference| relative_path_string(&reference.file))
            .unwrap_or_else(|| PROJECT_FILE.to_string());
        diagnostics.push(cross_file_diagnostic(
            "registryctl.authoring.project.invalid",
            &integration_file,
            Some("capability.snapshot"),
            "A snapshot integration does not match its entity contract.",
            "Align exact selectors and projected outputs with the referenced entity schema.",
            Some(INTEGRATION_SCHEMA_HINT),
            vec![
                diagnostic_address(&integration_file, &["capability", "snapshot"]),
                diagnostic_address(&entity_file, &["schema", "properties"]),
            ],
        ));
    }
    diagnostics
}

fn not_applicable_diagnostic(
    root: &Path,
    project: &RegistryProject,
    alias: &str,
    integration: &LoadedIntegration,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
) -> ProjectAuthoringDiagnostic {
    let integration_file = project
        .integrations
        .get(alias)
        .and_then(|reference| relative_path_string(&reference.file))
        .unwrap_or_else(|| PROJECT_FILE.to_string());
    let mut addresses = Vec::new();

    let fixture_named = |name: &str| {
        integration
            .fixtures
            .iter()
            .find(|(_, fixture)| fixture.name == name)
    };
    let invalid_evidence = |reason: &NotApplicableReason| {
        fixture_named(&reason.request_fixture).filter(|(_, fixture)| {
            fixture.interactions.is_empty()
                || fixture.expect.error.is_some()
                || !matches!(
                    fixture.expect.outcome.as_deref(),
                    None | Some("match" | "no_match")
                )
        })
    };
    let ambiguity_conflict = integration
        .document
        .not_applicable
        .ambiguity
        .as_ref()
        .and_then(|_| {
            integration
                .fixtures
                .iter()
                .find(|(_, fixture)| fixture.expect.outcome.as_deref() == Some("ambiguous"))
        });
    let ambiguity_evidence = integration
        .document
        .not_applicable
        .ambiguity
        .as_ref()
        .and_then(invalid_evidence);
    let subject_conflict = integration
        .document
        .not_applicable
        .subject_mismatch
        .as_ref()
        .and_then(|_| {
            integration.fixtures.iter().find(|(_, fixture)| {
                fixture.expect.error.as_deref() == Some("failure.subject_mismatch")
            })
        });
    let subject_evidence = integration
        .document
        .not_applicable
        .subject_mismatch
        .as_ref()
        .and_then(|reason| {
            invalid_evidence(reason).or_else(|| fixture_named(&reason.request_fixture))
        });
    let invalid_snapshot_ambiguity = match &integration.document.capability {
        CapabilityDeclaration::Snapshot { snapshot }
            if integration.document.not_applicable.ambiguity.is_some()
                && entities.get(&snapshot.entity).is_some_and(|entity| {
                    !snapshot.exact.contains_key(&entity.document.primary_key)
                }) =>
        {
            Some(snapshot)
        }
        _ => None,
    };
    if let Some((path, _)) = ambiguity_conflict {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "ambiguity"],
        ));
        addresses.push(diagnostic_address(
            &normalized_authored_file(root, path),
            &["expect", "outcome"],
        ));
    } else if let Some((path, fixture)) = ambiguity_evidence {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "ambiguity", "request_fixture"],
        ));
        addresses.push(not_applicable_evidence_address(root, path, fixture));
    } else if let Some(snapshot) = invalid_snapshot_ambiguity {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "ambiguity"],
        ));
        if entities.contains_key(&snapshot.entity) {
            let entity_file = project
                .entities
                .get(&snapshot.entity)
                .and_then(|reference| relative_path_string(&reference.file))
                .unwrap_or_else(|| PROJECT_FILE.to_string());
            addresses.push(diagnostic_address(&entity_file, &["primary_key"]));
        }
    } else if let Some((path, _)) = subject_conflict {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "subject_mismatch"],
        ));
        addresses.push(diagnostic_address(
            &normalized_authored_file(root, path),
            &["expect", "error"],
        ));
    } else if let Some((path, fixture)) = subject_evidence {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "subject_mismatch", "request_fixture"],
        ));
        addresses.push(not_applicable_evidence_address(root, path, fixture));
    } else if let Some((script_path, _)) = integration.script.as_ref() {
        addresses.push(diagnostic_address(
            &integration_file,
            &["not_applicable", "subject_mismatch"],
        ));
        addresses.push(diagnostic_address(
            &normalized_authored_file(root, script_path),
            &[],
        ));
    } else {
        addresses.push(diagnostic_address(&integration_file, &["not_applicable"]));
    }

    cross_file_diagnostic(
        "registryctl.authoring.fixture.invalid",
        &integration_file,
        Some("not_applicable"),
        "Fixture coverage is inconsistent with the integration contract.",
        "Correct the integration's not-applicable fixture declarations.",
        Some(INTEGRATION_SCHEMA_HINT),
        addresses,
    )
}

fn not_applicable_evidence_address(
    root: &Path,
    path: &Path,
    fixture: &FixtureDocument,
) -> ProjectAuthoringDiagnosticAddress {
    let pointer = if fixture.interactions.is_empty() {
        &["interactions"][..]
    } else if fixture.expect.error.is_some() {
        &["expect", "error"][..]
    } else {
        &["expect", "outcome"][..]
    };
    diagnostic_address(&normalized_authored_file(root, path), pointer)
}

fn fixture_set_diagnostics(
    root: &Path,
    integration_file: &Path,
    fixtures: &[(PathBuf, FixtureDocument)],
) -> Vec<ProjectAuthoringDiagnostic> {
    let integration_file =
        relative_path_string(integration_file).unwrap_or_else(|| PROJECT_FILE.to_string());
    let mut first_by_name = BTreeMap::new();
    for (path, fixture) in fixtures {
        if let Some(first) = first_by_name.insert(fixture.name.as_str(), path) {
            let first_file = normalized_authored_file(root, first);
            let second_file = normalized_authored_file(root, path);
            return vec![cross_file_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &second_file,
                Some("name"),
                "Fixture names are duplicated within one integration.",
                "Give every fixture in the integration a unique name.",
                Some(FIXTURE_SCHEMA_HINT),
                vec![
                    diagnostic_address(&first_file, &["name"]),
                    diagnostic_address(&second_file, &["name"]),
                    diagnostic_address(&integration_file, &["fixtures"]),
                ],
            )];
        }
    }
    fixtures.first().map_or_else(Vec::new, |(path, _)| {
        let file = normalized_authored_file(root, path);
        vec![cross_file_diagnostic(
            "registryctl.authoring.fixture.invalid",
            &file,
            Some("input"),
            "The fixture set is inconsistent with its integration contract.",
            "Use unique fixture names and satisfy the integration contract in every fixture.",
            Some(FIXTURE_SCHEMA_HINT),
            vec![
                diagnostic_address(&file, &["input"]),
                diagnostic_address(&integration_file, &["input"]),
            ],
        )]
    })
}

fn authored_fixture_body_paths(authored: &AuthoredFixtureDocument) -> Vec<&Path> {
    let mut paths = Vec::new();
    for interaction in &authored.interactions {
        if let Some(AuthoredFixtureBody::File(AuthoredFixtureBodyFile { file })) =
            interaction.expect.body.as_ref()
        {
            paths.push(file.as_path());
        }
        if let AuthoredFixtureResponse::Http(AuthoredFixtureHttpResponse {
            body: Some(AuthoredFixtureBody::File(AuthoredFixtureBodyFile { file })),
            ..
        }) = &interaction.respond
        {
            paths.push(file.as_path());
        }
    }
    paths
}

fn diagnostic_fixture_body_relative(fixture: &Path, body: &Path) -> Option<PathBuf> {
    let mut components = body.components();
    if components.next() != Some(Component::Normal(OsStr::new("bodies")))
        || components.next().is_none()
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(fixture.parent()?.join(body))
}

fn collect_integration_script(
    root: &Path,
    integration_path: &Path,
    integration_file: &str,
    loaded: &mut LoadedIntegration,
    diagnostics: &mut Vec<ProjectAuthoringDiagnostic>,
) -> DiagnosticResult<bool> {
    let Some(script_reference) = integration_script(&loaded.document) else {
        return Ok(false);
    };
    let parent = integration_path
        .parent()
        .ok_or_else(|| path_unsafe(integration_file, Some("capability.script.file")))?;
    let parent_relative = parent.strip_prefix(root).map_err(|_| {
        Box::new(path_unsafe(
            integration_file,
            Some("capability.script.file"),
        ))
    })?;
    let script_relative = diagnostic_join_relative(
        parent_relative,
        script_reference,
        integration_file,
        "capability.script.file",
    )?;
    let (script_path, script_bytes) = diagnostic_read_relative(
        root,
        &script_relative,
        Some("capability.script.file"),
        MAX_AUTHORED_FILE_BYTES,
    )?;
    let mut modules = Vec::new();
    let mut module_paths = BTreeSet::new();
    if let CapabilityDeclaration::Script { script } = &loaded.document.capability {
        for module in &script.modules {
            if module.extension().and_then(OsStr::to_str) != Some("rhai") {
                diagnostics.push(script_contract_diagnostic(
                    integration_file,
                    Some("capability.script.modules"),
                    None,
                    None,
                ));
                loaded.script = Some((script_path, script_bytes.into_boxed_slice()));
                loaded.script_modules = modules;
                return Ok(true);
            }
            let relative = diagnostic_join_relative(
                parent_relative,
                module,
                integration_file,
                "capability.script.modules",
            )?;
            if !module_paths.insert(relative.clone()) {
                diagnostics.push(script_contract_diagnostic(
                    integration_file,
                    Some("capability.script.modules"),
                    None,
                    None,
                ));
                loaded.script = Some((script_path, script_bytes.into_boxed_slice()));
                loaded.script_modules = modules;
                return Ok(true);
            }
            let (path, bytes) = diagnostic_read_relative(
                root,
                &relative,
                Some("capability.script.modules"),
                MAX_AUTHORED_FILE_BYTES,
            )?;
            modules.push((path, bytes.into_boxed_slice()));
        }
    }
    loaded.script = Some((script_path, script_bytes.into_boxed_slice()));
    loaded.script_modules = modules;
    let source = match compiled_rhai_source(loaded) {
        Ok(source) => source,
        Err(_) => {
            diagnostics.push(script_contract_diagnostic(
                integration_file,
                Some("capability.script.file"),
                None,
                None,
            ));
            return Ok(true);
        }
    };
    let source_text = match std::str::from_utf8(&source) {
        Ok(source) => source,
        Err(_) => {
            diagnostics.push(script_contract_diagnostic(
                integration_file,
                Some("capability.script.file"),
                None,
                None,
            ));
            return Ok(true);
        }
    };
    let probe = registry_relay::rhai_worker::probe_script_diagnostic(
        source_text,
        "consult",
        registry_relay::rhai_worker::WorkerLimits {
            max_operations: 100_000,
            max_call_levels: 16,
            max_expr_depth: 16,
            max_string_bytes: 64 * 1024,
            max_array_items: 1024,
            max_map_entries: 1024,
            max_output_bytes: 64 * 1024,
            max_ipc_frame_bytes: 256 * 1024,
            max_memory_bytes: 128 * 1024 * 1024,
            wall_time_ms: 250,
            max_source_calls: 16,
        },
    );
    let Err(probe) = probe else {
        return Ok(false);
    };
    let (path, line, field) = rhai_diagnostic_source(loaded, probe.line()).unwrap_or((
        loaded
            .script
            .as_ref()
            .expect("script is present")
            .0
            .as_path(),
        None,
        "capability.script.file",
    ));
    let file = normalized_authored_file(root, path);
    let (code, cause, remediation) = match probe.cause() {
        registry_relay::rhai_worker::ScriptProbeCause::SyntaxError => (
            "registryctl.authoring.script.syntax_error",
            "The Script source has invalid syntax.",
            "Correct the Script syntax at the reported location.",
        ),
        registry_relay::rhai_worker::ScriptProbeCause::UnknownFunction => (
            "registryctl.authoring.script.unknown_function",
            "The Script does not define the required entrypoint.",
            "Define consult(context) as the Script entrypoint.",
        ),
        registry_relay::rhai_worker::ScriptProbeCause::UnsupportedFunctionSignature => (
            "registryctl.authoring.script.invalid_signature",
            "The Script entrypoint has an invalid signature.",
            "Define the entrypoint with the exact consult(context) signature.",
        ),
        registry_relay::rhai_worker::ScriptProbeCause::ContractViolation => (
            "registryctl.authoring.script.closed_contract_violation",
            "The Script violates the closed authoring contract.",
            "Use only the released bounded Script contract.",
        ),
    };
    diagnostics.push(make_diagnostic(
        code,
        &file,
        Some(field),
        line,
        probe.column(),
        None,
        probe.valid_signatures().first().copied(),
        cause,
        remediation,
        Vec::new(),
    ));
    Ok(true)
}

fn collect_environment_semantics(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
    environment: &EnvironmentDocument,
    name: &str,
    diagnostics: &mut Vec<ProjectAuthoringDiagnostic>,
) {
    let file = format!("environments/{name}.yaml");
    let before = diagnostics.len();
    for (alias, loaded) in integrations {
        let Some(binding) = environment.integrations.get(alias) else {
            continue;
        };
        if validate_https_origin(&binding.source.origin, "integration source origin").is_err() {
            diagnostics.push(environment_invalid(
                &file,
                "integrations.source.origin",
                "An integration source origin is invalid.",
                "Use an exact HTTPS origin without a path, query, fragment, or credentials.",
            ));
        }
        if validate_source_credential_binding(
            alias,
            credential_interface(&loaded.document),
            &binding.source,
        )
        .is_err()
        {
            let integration_file = project
                .integrations
                .get(alias)
                .and_then(|reference| relative_path_string(&reference.file))
                .unwrap_or_else(|| PROJECT_FILE.to_string());
            diagnostics.push(cross_file_diagnostic(
                "registryctl.authoring.environment.invalid",
                &file,
                Some("integrations.source.credential"),
                "An integration credential binding is invalid.",
                "Match the credential shape and positive generation to the integration auth type.",
                Some(ENVIRONMENT_SCHEMA_HINT),
                vec![
                    diagnostic_address(&file, &["integrations", alias, "source", "credential"]),
                    diagnostic_address(&integration_file, &["source", "auth"]),
                ],
            ));
        }
    }
    if environment
        .relay
        .as_ref()
        .is_some_and(|relay| relay.allowed_clients.is_empty() && relay.local_api_keys.is_none())
    {
        diagnostics.push(environment_invalid(
            &file,
            "relay.allowed_clients",
            "The public Relay has no admitted OpenID Connect client.",
            "Add at least one intended Relay client id.",
        ));
    }
    if diagnostics.len() == before
        && validate_environment(project, integrations, entities, environment).is_err()
    {
        diagnostics.push(environment_relationship_diagnostic(
            project,
            integrations,
            entities,
            environment,
            &file,
        ));
    }
}

fn environment_relationship_diagnostic(
    project: &RegistryProject,
    integrations: &BTreeMap<String, LoadedIntegration>,
    entities: &BTreeMap<String, LoadedEntityDefinition>,
    environment: &EnvironmentDocument,
    file: &str,
) -> ProjectAuthoringDiagnostic {
    let mut addresses = Vec::new();

    for (alias, loaded) in integrations {
        let integration_file = project
            .integrations
            .get(alias)
            .and_then(|reference| relative_path_string(&reference.file))
            .unwrap_or_else(|| PROJECT_FILE.to_string());
        match &loaded.document.capability {
            CapabilityDeclaration::Snapshot { .. } => {
                if environment.integrations.contains_key(alias) {
                    addresses.push(diagnostic_address(file, &["integrations", alias]));
                    addresses.push(diagnostic_address(
                        &integration_file,
                        &["capability", "snapshot"],
                    ));
                    break;
                }
            }
            CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
                let Some(binding) = environment.integrations.get(alias) else {
                    addresses.push(diagnostic_address(file, &["integrations"]));
                    addresses.push(diagnostic_address(&integration_file, &["capability"]));
                    break;
                };
                if validate_source_binding(alias, &loaded.document, &binding.source).is_err() {
                    addresses.push(diagnostic_address(file, &["integrations", alias, "source"]));
                    addresses.push(diagnostic_address(&integration_file, &["source"]));
                    break;
                }
            }
        }
    }
    if addresses.is_empty() {
        if let Some(alias) = environment
            .integrations
            .keys()
            .find(|alias| !integrations.contains_key(*alias))
        {
            addresses.push(diagnostic_address(file, &["integrations", alias]));
            addresses.push(diagnostic_address(PROJECT_FILE, &["integrations"]));
        }
    }
    if addresses.is_empty() {
        for (entity_id, loaded) in entities {
            let entity_file = project
                .entities
                .get(entity_id)
                .and_then(|reference| relative_path_string(&reference.file))
                .unwrap_or_else(|| PROJECT_FILE.to_string());
            let Some(binding) = environment.entities.get(entity_id) else {
                addresses.push(diagnostic_address(file, &["entities"]));
                addresses.push(diagnostic_address(&entity_file, &[]));
                break;
            };
            if validate_environment_entity(&loaded.document, binding).is_err() {
                addresses.push(diagnostic_address(
                    file,
                    &["entities", entity_id, "columns"],
                ));
                addresses.push(diagnostic_address(&entity_file, &["schema", "properties"]));
                break;
            }
        }
    }
    if addresses.is_empty() {
        if let Some(entity_id) = environment
            .entities
            .keys()
            .find(|entity_id| !entities.contains_key(*entity_id))
        {
            addresses.push(diagnostic_address(file, &["entities", entity_id]));
            addresses.push(diagnostic_address(PROJECT_FILE, &["entities"]));
        }
    }
    if addresses.is_empty() {
        addresses.push(diagnostic_address(file, &["deployment"]));
        addresses.push(diagnostic_address(PROJECT_FILE, &["services"]));
    }

    cross_file_diagnostic(
        "registryctl.authoring.environment.invalid",
        file,
        Some("deployment"),
        "The environment binding is invalid.",
        "Align deployment, integration, entity, caller, and product bindings with the project.",
        Some(ENVIRONMENT_SCHEMA_HINT),
        addresses,
    )
}

fn inspect_environment_file_boundaries(root: &Path) -> DiagnosticResult<()> {
    let relative_directory = Path::new("environments");
    let directory = root.join(relative_directory);
    let field = Some("environments");
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Box::new(file_unreadable("environments", field))),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Box::new(path_unsafe("environments", field)));
    }

    let entries =
        fs::read_dir(&directory).map_err(|_| Box::new(file_unreadable("environments", field)))?;
    let mut environment_files = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_ENVIRONMENT_DIRECTORY_ENTRIES {
            return Err(Box::new(environment_invalid(
                "environments",
                "environments",
                "The environment directory exceeds its fixed entry bound.",
                "Keep at most 128 direct entries and at most 64 YAML environments.",
            )));
        }
        let entry = entry.map_err(|_| Box::new(file_unreadable("environments", field)))?;
        let path = entry.path();
        if path.extension().and_then(OsStr::to_str) != Some("yaml") {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Box::new(path_unsafe("environments", field)))?;
        if relative_path_string(relative).is_none() {
            return Err(Box::new(path_unsafe("environments", field)));
        }
        environment_files.push(relative.to_path_buf());
    }
    environment_files.sort_by(|left, right| {
        left.as_os_str()
            .as_encoded_bytes()
            .cmp(right.as_os_str().as_encoded_bytes())
    });
    if environment_files.len() > MAX_ENVIRONMENTS {
        return Err(Box::new(environment_invalid(
            "environments",
            "environments",
            "The project declares too many environments.",
            "Keep no more than 64 YAML environment files.",
        )));
    }
    for relative in environment_files {
        diagnostic_read_relative_classified(root, &relative, field, MAX_AUTHORED_FILE_BYTES)
            .map_err(DiagnosticReadFailure::into_diagnostic)?;
    }
    Ok(())
}

fn diagnostic_project_root(root: &Path) -> DiagnosticResult<PathBuf> {
    let metadata =
        fs::symlink_metadata(root).map_err(|_| Box::new(file_unreadable(PROJECT_FILE, None)))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Box::new(path_unsafe(PROJECT_FILE, None)));
    }
    root.canonicalize()
        .map_err(|_| Box::new(file_unreadable(PROJECT_FILE, None)))
}

fn diagnostic_directory(
    root: &Path,
    relative: &Path,
    field: Option<&'static str>,
) -> DiagnosticResult<PathBuf> {
    if validate_relative_authored_path(relative).is_err() {
        return Err(Box::new(path_unsafe(PROJECT_FILE, field)));
    }
    let path = root.join(relative);
    diagnostic_reject_symlink_components(root, &path, PROJECT_FILE, field)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| Box::new(file_unreadable(&relative_or_fallback(root, &path), field)))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Box::new(path_unsafe(
            &relative_or_fallback(root, &path),
            field,
        )));
    }
    Ok(path)
}

fn diagnostic_read_relative(
    root: &Path,
    relative: &Path,
    field: Option<&'static str>,
    max_bytes: u64,
) -> DiagnosticResult<(PathBuf, Vec<u8>)> {
    diagnostic_read_relative_classified(root, relative, field, max_bytes)
        .map_err(DiagnosticReadFailure::into_diagnostic)
}

fn diagnostic_read_relative_classified(
    root: &Path,
    relative: &Path,
    field: Option<&'static str>,
    max_bytes: u64,
) -> std::result::Result<(PathBuf, Vec<u8>), DiagnosticReadFailure> {
    if validate_relative_authored_path(relative).is_err() {
        return Err(DiagnosticReadFailure::Terminal(Box::new(path_unsafe(
            PROJECT_FILE,
            field,
        ))));
    }
    let path = root.join(relative);
    let file = relative_path_string(relative).unwrap_or_else(|| PROJECT_FILE.to_string());
    diagnostic_reject_symlink_components(root, &path, &file, field)
        .map_err(DiagnosticReadFailure::Terminal)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(DiagnosticReadFailure::Missing(Box::new(file_unreadable(
                &file, field,
            ))));
        }
        Err(_) => {
            return Err(DiagnosticReadFailure::Terminal(Box::new(file_unreadable(
                &file, field,
            ))));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DiagnosticReadFailure::Terminal(Box::new(path_unsafe(
            &file, field,
        ))));
    }
    if metadata.len() > max_bytes {
        return Err(DiagnosticReadFailure::Terminal(Box::new(file_too_large(
            &file, field,
        ))));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| DiagnosticReadFailure::Terminal(Box::new(file_unreadable(&file, field))))?;
    if !canonical.starts_with(root) {
        return Err(DiagnosticReadFailure::Terminal(Box::new(path_unsafe(
            PROJECT_FILE,
            field,
        ))));
    }
    let bytes = fs::read(&canonical)
        .map_err(|_| DiagnosticReadFailure::Terminal(Box::new(file_unreadable(&file, field))))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(DiagnosticReadFailure::Terminal(Box::new(file_too_large(
            &file, field,
        ))));
    }
    Ok((canonical, bytes))
}

fn diagnostic_reject_symlink_components(
    root: &Path,
    path: &Path,
    file: &str,
    field: Option<&'static str>,
) -> DiagnosticResult<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Box::new(path_unsafe(PROJECT_FILE, field)))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(Box::new(path_unsafe(PROJECT_FILE, field)));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Box::new(path_unsafe(file, field)));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Box::new(file_unreadable(file, field))),
        }
    }
    Ok(())
}

fn diagnostic_join_relative(
    parent: &Path,
    relative: &Path,
    authored_file: &str,
    field: &'static str,
) -> DiagnosticResult<PathBuf> {
    if validate_relative_authored_path(relative).is_err() {
        return Err(Box::new(path_unsafe(authored_file, Some(field))));
    }
    let joined = parent.join(relative);
    if validate_relative_authored_path(&joined).is_err() {
        return Err(Box::new(path_unsafe(authored_file, Some(field))));
    }
    Ok(joined)
}

fn diagnostic_parse_yaml<T: CurrentAuthoringDocument>(
    bytes: &[u8],
    file: &str,
    kind: &'static str,
    schema_hint: &'static str,
) -> DiagnosticResult<T> {
    parse_current_authoring_document(bytes).map_err(|error| {
        if error.is_unsafe_authored_path() {
            return Box::new(path_unsafe(file, None));
        }
        let reserved_fixture_body = error.is_reserved_fixture_body();
        let unknown_field = error.keyword() == Some("additionalProperties");
        let syntax = error.is_syntax();
        let schema_code = match T::KIND {
            ProjectSchemaKind::Project => "registryctl.authoring.project.invalid",
            ProjectSchemaKind::Environment => {
                "registryctl.authoring.environment.invalid"
            }
            ProjectSchemaKind::Integration => {
                "registryctl.authoring.integration.invalid"
            }
            ProjectSchemaKind::Fixture => "registryctl.authoring.fixture.invalid",
            ProjectSchemaKind::Entity => "registryctl.authoring.entity.invalid",
        };
        let (line, column) = error.location();
        let instance_path = error.instance_path().map(str::to_string);
        let mut diagnostic = make_diagnostic(
            if reserved_fixture_body {
                "registryctl.authoring.fixture.reserved_body_field"
            } else if unknown_field {
                "registryctl.authoring.yaml.unknown_field"
            } else if syntax {
                "registryctl.authoring.yaml.invalid_syntax"
            } else {
                schema_code
            },
            file,
            reserved_fixture_body.then_some("interactions.body"),
            line,
            column,
            Some(schema_hint),
            None,
            if reserved_fixture_body {
                "A fixture body object uses the reserved top-level `file` field without matching the closed file-reference shape."
            } else if unknown_field {
                "The YAML document contains an unknown field."
            } else if syntax {
                "The YAML document has invalid syntax."
            } else {
                "The YAML document does not satisfy its canonical authoring schema."
            },
            if reserved_fixture_body {
                FIXTURE_BODY_FILE_REFERENCE_REMEDIATION
            } else {
                match kind {
                    "project" => "Correct the project YAML using the project authoring schema. If this project passed with a pre-1.0 Registryctl, create a separate 1.0 project with the `spreadsheet` or `http` template that matches the source, then copy only reviewed authored intent. Registryctl does not migrate or approve the source project.",
                    "entity" => "Correct the entity YAML using the entity authoring schema.",
                    "integration" => {
                        "Correct the integration YAML using the integration authoring schema."
                    }
                    "fixture" => "Correct the fixture YAML using the fixture authoring schema.",
                    "environment" => {
                        "Correct the environment YAML using the environment authoring schema."
                    }
                    _ => "Correct the YAML using the matching authoring schema.",
                }
            },
            Vec::new(),
        );
        if let Some(pointer) = instance_path {
            diagnostic.addresses = vec![ProjectAuthoringDiagnosticAddress {
                file: file.to_string(),
                pointer,
            }];
        }
        Box::new(diagnostic)
    })
}

fn finalized_diagnostics(
    mut diagnostics: Vec<ProjectAuthoringDiagnostic>,
) -> ProjectAuthoringDiagnostics {
    diagnostics.sort_by(|left, right| {
        left.file
            .as_bytes()
            .cmp(right.file.as_bytes())
            .then_with(|| left.line.unwrap_or(0).cmp(&right.line.unwrap_or(0)))
            .then_with(|| left.column.unwrap_or(0).cmp(&right.column.unwrap_or(0)))
            .then_with(|| left.field.unwrap_or("").cmp(right.field.unwrap_or("")))
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| diagnostic_addresses_cmp(&left.addresses, &right.addresses))
            .then_with(|| left.cause.cmp(right.cause))
            .then_with(|| left.remediation.cmp(right.remediation))
            .then_with(|| left.schema_hint.cmp(&right.schema_hint))
            .then_with(|| left.suggestion.cmp(&right.suggestion))
    });
    diagnostics.dedup();
    if diagnostics.len() > MAX_AUTHORING_DIAGNOSTICS {
        diagnostics.truncate(MAX_AUTHORING_DIAGNOSTICS - 1);
        diagnostics.push(make_diagnostic(
            "registryctl.authoring.diagnostics.truncated",
            PROJECT_FILE,
            None,
            None,
            None,
            None,
            None,
            "Additional authoring diagnostics were omitted at the fixed limit.",
            "Fix the reported diagnostics, then run project check again.",
            Vec::new(),
        ));
    }
    ProjectAuthoringDiagnostics {
        schema_version: PROJECT_DIAGNOSTICS_SCHEMA_VERSION,
        status: "invalid",
        diagnostics,
    }
}

fn diagnostic_addresses_cmp(
    left: &[ProjectAuthoringDiagnosticAddress],
    right: &[ProjectAuthoringDiagnosticAddress],
) -> std::cmp::Ordering {
    left.iter()
        .zip(right)
        .find_map(|(left, right)| {
            let ordering = left
                .file
                .as_bytes()
                .cmp(right.file.as_bytes())
                .then_with(|| left.pointer.as_bytes().cmp(right.pointer.as_bytes()));
            ordering.ne(&std::cmp::Ordering::Equal).then_some(ordering)
        })
        .unwrap_or_else(|| left.len().cmp(&right.len()))
}

fn terminal_diagnostic_code(code: &str) -> bool {
    matches!(
        code,
        "registryctl.authoring.path.unsafe"
            | "registryctl.authoring.file.unreadable"
            | "registryctl.authoring.file.too_large"
    )
}

/// Constructs an emitted authoring diagnostic from the one catalog authority.
///
/// `additional_addresses` is intentionally available for relationship
/// validators to attach both authored sides without changing the legacy
/// single-file/field rendering contract. Existing collectors currently use
/// the primary location; relation emitters can opt in as they gain exact
/// source locations.
#[allow(clippy::too_many_arguments)]
fn make_diagnostic(
    code: &str,
    file: &str,
    field: Option<&'static str>,
    line: Option<usize>,
    column: Option<usize>,
    schema_hint: Option<&'static str>,
    suggestion: Option<&'static str>,
    cause: &'static str,
    remediation: &'static str,
    mut additional_addresses: Vec<ProjectAuthoringDiagnosticAddress>,
) -> ProjectAuthoringDiagnostic {
    let definition = diagnostic_definition(code);
    let primary = ProjectAuthoringDiagnosticAddress {
        file: file.to_string(),
        pointer: authored_field_pointer(field),
    };
    additional_addresses.retain(|address| address != &primary);
    let mut addresses = vec![primary];
    addresses.extend(additional_addresses);
    addresses.sort_by(|left, right| {
        left.file
            .as_bytes()
            .cmp(right.file.as_bytes())
            .then_with(|| left.pointer.as_bytes().cmp(right.pointer.as_bytes()))
    });
    addresses.dedup();
    ProjectAuthoringDiagnostic {
        code: definition.code,
        file: file.to_string(),
        field,
        line,
        column,
        schema_hint,
        suggestion,
        addresses,
        phase: definition.phase,
        rule: definition.rule,
        accepted: definition.accepted,
        safe_summary_policy: definition.safe_summary_policy,
        received_summary: match definition.safe_summary_policy {
            "no_received_value" => "not_disclosed_by_policy",
            "received_type_only" => "invalid_type_or_shape",
            _ => unreachable!("catalog summary policy is closed"),
        },
        documentation: definition.documentation,
        replacement: definition.replacement,
        changed_behavior: definition.changed_behavior,
        cause,
        remediation,
    }
}

fn authored_field_pointer(field: Option<&str>) -> String {
    let Some(field) = field else {
        return String::new();
    };
    let mut pointer = String::new();
    for segment in field.split('.') {
        pointer.push('/');
        pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}

fn invalid_diagnostic(
    code: &'static str,
    file: &str,
    field: Option<&'static str>,
    cause: &'static str,
    remediation: &'static str,
    schema_hint: Option<&'static str>,
) -> ProjectAuthoringDiagnostic {
    make_diagnostic(
        code,
        file,
        field,
        None,
        None,
        schema_hint,
        None,
        cause,
        remediation,
        Vec::new(),
    )
}

fn cross_file_diagnostic(
    code: &'static str,
    file: &str,
    field: Option<&'static str>,
    cause: &'static str,
    remediation: &'static str,
    schema_hint: Option<&'static str>,
    mut addresses: Vec<ProjectAuthoringDiagnosticAddress>,
) -> ProjectAuthoringDiagnostic {
    addresses.sort_by(|left, right| {
        left.file
            .as_bytes()
            .cmp(right.file.as_bytes())
            .then_with(|| left.pointer.as_bytes().cmp(right.pointer.as_bytes()))
    });
    addresses.dedup();
    let mut diagnostic = invalid_diagnostic(code, file, field, cause, remediation, schema_hint);
    if !addresses.is_empty() {
        diagnostic.addresses = addresses;
    }
    diagnostic
}

fn diagnostic_address(file: &str, segments: &[&str]) -> ProjectAuthoringDiagnosticAddress {
    let mut pointer = String::new();
    for segment in segments {
        pointer.push('/');
        pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    }
    ProjectAuthoringDiagnosticAddress {
        file: file.to_string(),
        pointer,
    }
}

fn environment_invalid(
    file: &str,
    field: &'static str,
    cause: &'static str,
    remediation: &'static str,
) -> ProjectAuthoringDiagnostic {
    invalid_diagnostic(
        "registryctl.authoring.environment.invalid",
        file,
        Some(field),
        cause,
        remediation,
        Some(ENVIRONMENT_SCHEMA_HINT),
    )
}

fn script_contract_diagnostic(
    file: &str,
    field: Option<&'static str>,
    line: Option<usize>,
    column: Option<usize>,
) -> ProjectAuthoringDiagnostic {
    make_diagnostic(
        "registryctl.authoring.script.closed_contract_violation",
        file,
        field,
        line,
        column,
        None,
        None,
        "The Script violates the closed authoring contract.",
        "Use only the released bounded Script contract.",
        Vec::new(),
    )
}

fn path_unsafe(file: &str, field: Option<&'static str>) -> ProjectAuthoringDiagnostic {
    invalid_diagnostic(
        "registryctl.authoring.path.unsafe",
        file,
        field,
        "An authored path is unsafe.",
        "Use a normalized project-relative path to a regular non-symlink file.",
        None,
    )
}

fn file_unreadable(file: &str, field: Option<&'static str>) -> ProjectAuthoringDiagnostic {
    invalid_diagnostic(
        "registryctl.authoring.file.unreadable",
        file,
        field,
        "An authored file cannot be read.",
        "Restore a readable regular file inside the project root.",
        None,
    )
}

fn file_too_large(file: &str, field: Option<&'static str>) -> ProjectAuthoringDiagnostic {
    invalid_diagnostic(
        "registryctl.authoring.file.too_large",
        file,
        field,
        "An authored file exceeds its fixed size bound.",
        "Reduce the authored file below the documented bound.",
        None,
    )
}

fn normalized_authored_file(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .and_then(relative_path_string)
        .unwrap_or_else(|| PROJECT_FILE.to_string())
}

fn relative_or_fallback(root: &Path, path: &Path) -> String {
    normalized_authored_file(root, path)
}

fn relative_path_string(path: &Path) -> Option<String> {
    let mut output = String::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return None;
        };
        let component = component.to_str()?;
        if !output.is_empty() {
            output.push('/');
        }
        output.push_str(component);
    }
    (!output.is_empty()).then_some(output)
}

#[cfg(test)]
mod diagnostic_catalog_tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn canonical_catalog_fixture_is_exact_and_deterministic() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/project-reports/registryctl.project_authoring_diagnostic_catalog.v1.json"
        ))
        .expect("catalog fixture parses");
        let rendered = serde_json::to_value(project_authoring_diagnostic_catalog())
            .expect("catalog serializes");
        assert_eq!(rendered, fixture);

        let codes = AUTHORING_DIAGNOSTIC_CATALOG
            .iter()
            .map(|definition| definition.code)
            .collect::<Vec<_>>();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        assert_eq!(codes, sorted, "catalog ordering is deterministic");
        assert_eq!(codes.len(), 17);
        assert_eq!(codes.iter().collect::<BTreeSet<_>>().len(), codes.len());
    }

    #[test]
    fn every_literal_emitted_authoring_code_has_one_catalog_definition() {
        let source = include_str!("diagnostics.rs");
        let emitted = source
            .split('"')
            .filter(|fragment| {
                fragment
                    .strip_prefix("registryctl.authoring.")
                    .is_some_and(|suffix| !suffix.is_empty())
            })
            .collect::<BTreeSet<_>>();
        let catalogued = AUTHORING_DIAGNOSTIC_CATALOG
            .iter()
            .map(|definition| definition.code)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            emitted, catalogued,
            "every literal emitted authoring code must be represented by the generated catalog"
        );
    }

    #[test]
    fn typed_address_is_rfc6901() {
        let diagnostic = make_diagnostic(
            "registryctl.authoring.yaml.unknown_field",
            "integrations/example/fixture.yaml",
            Some("interactions.body"),
            Some(7),
            Some(3),
            None,
            None,
            "The YAML document contains an unknown field.",
            "Correct the fixture YAML using the fixture authoring schema.",
            vec![ProjectAuthoringDiagnosticAddress {
                file: "registry-stack.yaml".to_string(),
                pointer: "/services/example".to_string(),
            }],
        );
        assert_eq!(diagnostic.addresses[0].pointer, "/interactions/body");
        assert_eq!(diagnostic.addresses.len(), 2);
    }

    #[test]
    fn parser_diagnostic_never_carries_planted_invalid_scalars() {
        for (input, sentinel) in [
            (
                br#"
version: secret-sentinel
registry:
  id: synthetic-registry
services: {}
"#
                .as_slice(),
                "secret-sentinel",
            ),
            (
                br#"
version: 1
registry: personal-sentinel
services: {}
"#
                .as_slice(),
                "personal-sentinel",
            ),
        ] {
            let raw_error = serde_norway::from_slice::<RegistryProject>(input)
                .expect_err("control parser rejects planted invalid scalar");
            assert!(
                raw_error.to_string().contains(sentinel),
                "negative control must place {sentinel:?} on a parser error path that could leak it"
            );
            let diagnostic = diagnostic_parse_yaml::<RegistryProject>(
                input,
                PROJECT_FILE,
                "project",
                PROJECT_SCHEMA_HINT,
            )
            .expect_err("planted invalid scalar is rejected");
            assert_eq!(diagnostic.code, "registryctl.authoring.project.invalid");
            let serialized = serde_json::to_string(&diagnostic).expect("diagnostic serializes");
            assert!(
                !serialized.contains(sentinel),
                "parser diagnostic leaked planted scalar {sentinel:?}"
            );
        }
    }

    #[test]
    fn dynamic_relationship_address_escapes_each_rfc6901_segment() {
        assert_eq!(
            diagnostic_address(
                "registry-stack.yaml",
                &["services", "service/with~reserved", "input"],
            )
            .pointer,
            "/services/service~1with~0reserved/input"
        );
    }

    #[test]
    fn finalization_only_collapses_fully_identical_diagnostics() {
        let make = |service: &str| {
            cross_file_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services.consultations"),
                "A service consultation does not match its integration.",
                "Align each consultation input with its referenced integration.",
                Some(PROJECT_SCHEMA_HINT),
                vec![
                    diagnostic_address(
                        PROJECT_FILE,
                        &["services", service, "consultations", "person", "input"],
                    ),
                    diagnostic_address("integrations/person/integration.yaml", &["input"]),
                ],
            )
        };
        let alpha = make("alpha");
        let beta = make("beta");
        let report = finalized_diagnostics(vec![beta.clone(), alpha.clone(), alpha.clone()]);
        assert_eq!(report.diagnostics, vec![alpha, beta]);
    }
}
