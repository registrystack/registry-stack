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
const ENTITY_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind entity > entity.schema.json";
const INTEGRATION_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind integration > integration.schema.json";
const FIXTURE_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind fixture > fixture.schema.json";
const ENVIRONMENT_SCHEMA_HINT: &str =
    "registryctl authoring schema --kind environment > environment.schema.json";

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
        if report.diagnostics.len() == 1 { "" } else { "s" }
    );
    for diagnostic in &report.diagnostics {
        let _ = write!(output, "\n{}", diagnostic.file);
        if let Some(line) = diagnostic.line {
            let _ = write!(output, ":{line}");
            if let Some(column) = diagnostic.column {
                let _ = write!(output, ":{column}");
            }
        }
        let _ = write!(
            output,
            " [{}] {}",
            diagnostic.code, diagnostic.cause
        );
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
    let project: RegistryProject = match diagnostic_parse_yaml(
        &project_bytes,
        PROJECT_FILE,
        "project",
        PROJECT_SCHEMA_HINT,
    ) {
        Ok(project) => project,
        Err(diagnostic) => {
            diagnostics.push(*diagnostic);
            collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
            return finalized_diagnostics(diagnostics);
        }
    };

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
        let document: EntityDefinition = match diagnostic_parse_yaml(
            &bytes,
            &file,
            "entity",
            ENTITY_SCHEMA_HINT,
        ) {
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
        let authored: AuthoredIntegrationDocument = match diagnostic_parse_yaml(
            &bytes,
            &file,
            "integration",
            INTEGRATION_SCHEMA_HINT,
        ) {
            Ok(document) => document,
            Err(diagnostic) => {
                diagnostics.push(*diagnostic);
                continue;
            }
        };
        if matches!(
            &authored.capability,
            AuthoredCapabilityDeclaration::Snapshot { snapshot }
                if !entities.contains_key(&snapshot.entity)
        ) {
            continue;
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
    let environment = collect_selected_environment_syntax(&root, environment_name, &mut diagnostics);
    if diagnostics[before_environment..]
        .iter()
        .any(|diagnostic| terminal_diagnostic_code(diagnostic.code))
    {
        return finalized_diagnostics(diagnostics);
    }
    let all_integrations_loaded = integrations.len() == project.integrations.len();
    if all_entities_loaded && all_integrations_loaded {
        if validate_service_integration_links(&project, &integrations).is_err() {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services.consultations"),
                "A service consultation does not match its integration.",
                "Align each consultation input with its referenced integration.",
                Some(PROJECT_SCHEMA_HINT),
            ));
        }
        if validate_project_entity_links(&project, &integrations, &entities).is_err() {
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.project.invalid",
                PROJECT_FILE,
                Some("services"),
                "A project entity reference is inconsistent.",
                "Align services, snapshots, and relationships with declared entities.",
                Some(PROJECT_SCHEMA_HINT),
            ));
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
                diagnostics.push(invalid_diagnostic(
                    "registryctl.authoring.fixture.invalid",
                    &normalized_authored_file(
                        &root,
                        &root.join(&project.integrations[alias].file),
                    ),
                    Some("not_applicable"),
                    "Fixture coverage is inconsistent with the integration contract.",
                    "Correct the integration's not-applicable fixture declarations.",
                    Some(INTEGRATION_SCHEMA_HINT),
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
        let (_, bytes) = diagnostic_read_relative(
            root,
            relative,
            Some("fixture"),
            MAX_AUTHORED_FILE_BYTES,
        )?;
        let file = relative_path_string(relative).unwrap_or_else(|| "fixtures".to_string());
        let authored: AuthoredFixtureDocument = match diagnostic_parse_yaml(
            &bytes,
            &file,
            "fixture",
            FIXTURE_SCHEMA_HINT,
        ) {
            Ok(document) => document,
            Err(diagnostic) => {
                diagnostics.push(*diagnostic);
                complete = false;
                continue;
            }
        };
        for body in authored_fixture_body_paths(&authored) {
            let Some(body_relative) = diagnostic_fixture_body_relative(relative, body) else {
                return Err(Box::new(path_unsafe(
                    &file,
                    Some("interactions.body"),
                )));
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
            diagnostics.push(invalid_diagnostic(
                "registryctl.authoring.fixture.invalid",
                &file,
                None,
                "The fixture does not satisfy its integration contract.",
                "Correct fixture inputs, interactions, and expectations without using live values.",
                Some(FIXTURE_SCHEMA_HINT),
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
        diagnostics.push(invalid_diagnostic(
            "registryctl.authoring.fixture.invalid",
            &relative_or_fallback(root, &directory_path),
            Some("fixtures"),
            "The fixture set is inconsistent with its integration contract.",
            "Use unique fixture names and satisfy the integration contract in every fixture.",
            Some(FIXTURE_SCHEMA_HINT),
        ));
        complete = false;
    }
    fixtures.sort_by(|left, right| left.1.name.as_bytes().cmp(right.1.name.as_bytes()));
    Ok((fixtures, complete))
}

fn authored_fixture_body_paths(authored: &AuthoredFixtureDocument) -> Vec<&Path> {
    let mut paths = Vec::new();
    for interaction in &authored.interactions {
        if let Some(AuthoredFixtureBody::File { file }) = interaction.expect.body.as_ref() {
            paths.push(file.as_path());
        }
        if let AuthoredFixtureResponse::Http {
            body: Some(AuthoredFixtureBody::File { file }),
            ..
        } = &interaction.respond
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
    let parent_relative = parent
        .strip_prefix(root)
        .map_err(|_| {
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
        loaded.script.as_ref().expect("script is present").0.as_path(),
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
    diagnostics.push(ProjectAuthoringDiagnostic {
        code,
        file,
        field: Some(field),
        line,
        column: probe.column(),
        schema_hint: None,
        suggestion: probe.valid_signatures().first().copied(),
        cause,
        remediation,
    });
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
            diagnostics.push(environment_invalid(
                &file,
                "integrations.source.credential",
                "An integration credential binding is invalid.",
                "Match the credential shape and positive generation to the integration auth type.",
            ));
        }
    }
    if let Some(issuance) = &environment.issuance {
        if issuance.generation == 0
            || validate_secret_reference(&issuance.signing_key).is_err()
            || validate_token(&issuance.issuer, "issuance issuer", 2048).is_err()
            || validate_token(&issuance.signing_kid, "issuance signing kid", 2048).is_err()
        {
            diagnostics.push(environment_invalid(
                &file,
                "issuance",
                "The issuance binding is invalid.",
                "Use bounded issuer metadata, a safe secret reference, and a positive generation.",
            ));
        }
    }
    if diagnostics.len() == before
        && validate_environment(project, integrations, entities, environment).is_err()
    {
        diagnostics.push(environment_invalid(
            &file,
            "deployment",
            "The environment binding is invalid.",
            "Align deployment, integration, entity, caller, and product bindings with the project.",
        ));
    }
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

    let entries = fs::read_dir(&directory)
        .map_err(|_| Box::new(file_unreadable("environments", field)))?;
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
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| Box::new(file_unreadable(PROJECT_FILE, None)))?;
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
            return Err(DiagnosticReadFailure::Terminal(Box::new(
                file_unreadable(&file, field),
            )));
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
    let canonical = path.canonicalize().map_err(|_| {
        DiagnosticReadFailure::Terminal(Box::new(file_unreadable(&file, field)))
    })?;
    if !canonical.starts_with(root) {
        return Err(DiagnosticReadFailure::Terminal(Box::new(path_unsafe(
            PROJECT_FILE,
            field,
        ))));
    }
    let bytes = fs::read(&canonical).map_err(|_| {
        DiagnosticReadFailure::Terminal(Box::new(file_unreadable(&file, field)))
    })?;
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

fn diagnostic_parse_yaml<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    file: &str,
    kind: &'static str,
    schema_hint: &'static str,
) -> DiagnosticResult<T> {
    serde_yaml::from_slice(bytes).map_err(|error| {
        let unknown_field = error.to_string().contains("unknown field");
        let location = error.location();
        Box::new(ProjectAuthoringDiagnostic {
            code: if unknown_field {
                "registryctl.authoring.yaml.unknown_field"
            } else {
                "registryctl.authoring.yaml.invalid_syntax"
            },
            file: file.to_string(),
            field: None,
            line: location.as_ref().map(serde_yaml::Location::line),
            column: location.as_ref().map(serde_yaml::Location::column),
            schema_hint: Some(schema_hint),
            suggestion: None,
            cause: if unknown_field {
                "The YAML document contains an unknown field."
            } else {
                "The YAML document has invalid syntax or shape."
            },
            remediation: match kind {
                "project" => "Correct the project YAML using the project authoring schema.",
                "entity" => "Correct the entity YAML using the entity authoring schema.",
                "integration" => {
                    "Correct the integration YAML using the integration authoring schema."
                }
                "fixture" => "Correct the fixture YAML using the fixture authoring schema.",
                "environment" => {
                    "Correct the environment YAML using the environment authoring schema."
                }
                _ => "Correct the YAML using the matching authoring schema.",
            },
        })
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
    });
    diagnostics.dedup_by(|left, right| {
        left.code == right.code
            && left.file == right.file
            && left.field == right.field
            && left.line == right.line
            && left.column == right.column
    });
    if diagnostics.len() > MAX_AUTHORING_DIAGNOSTICS {
        diagnostics.truncate(MAX_AUTHORING_DIAGNOSTICS - 1);
        diagnostics.push(ProjectAuthoringDiagnostic {
            code: "registryctl.authoring.diagnostics.truncated",
            file: PROJECT_FILE.to_string(),
            field: None,
            line: None,
            column: None,
            schema_hint: None,
            suggestion: None,
            cause: "Additional authoring diagnostics were omitted at the fixed limit.",
            remediation: "Fix the reported diagnostics, then run project check again.",
        });
    }
    ProjectAuthoringDiagnostics {
        status: "invalid",
        diagnostics,
    }
}

fn terminal_diagnostic_code(code: &str) -> bool {
    matches!(
        code,
        "registryctl.authoring.path.unsafe"
            | "registryctl.authoring.file.unreadable"
            | "registryctl.authoring.file.too_large"
    )
}

fn invalid_diagnostic(
    code: &'static str,
    file: &str,
    field: Option<&'static str>,
    cause: &'static str,
    remediation: &'static str,
    schema_hint: Option<&'static str>,
) -> ProjectAuthoringDiagnostic {
    ProjectAuthoringDiagnostic {
        code,
        file: file.to_string(),
        field,
        line: None,
        column: None,
        schema_hint,
        suggestion: None,
        cause,
        remediation,
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
    ProjectAuthoringDiagnostic {
        code: "registryctl.authoring.script.closed_contract_violation",
        file: file.to_string(),
        field,
        line,
        column,
        schema_hint: None,
        suggestion: None,
        cause: "The Script violates the closed authoring contract.",
        remediation: "Use only the released bounded Script contract.",
    }
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
