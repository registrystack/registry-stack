// SPDX-License-Identifier: Apache-2.0

struct StagedProjectInit {
    project: String,
    starter_id: String,
    starter_release: String,
    starter_content_digest: String,
}

pub fn init_registry_project(options: &ProjectInitOptions) -> Result<crate::InitReport> {
    let destination_existed = preflight_project_init_destination(&options.directory)?;
    let starter = options.starter.embedded()?;
    let parent = options
        .directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    create_dir_owner_only(parent).context("failed to create project destination parent")?;
    let staging = tempfile::Builder::new()
        .prefix(".registry-stack-init.transaction-")
        .tempdir_in(parent)
        .context("failed to create private project initialization staging")?;

    let staged = match stage_registry_project_init(starter, options.starter, staging.path()) {
        Ok(staged) => staged,
        Err(error) => {
            return match staging.close() {
                Ok(()) => Err(error.context("project initialization staging was discarded")),
                Err(cleanup_error) => Err(error.context(format!(
                    "failed to discard private project initialization staging: {cleanup_error}"
                ))),
            };
        }
    };

    match (destination_existed, preflight_project_init_destination(&options.directory)?) {
        (false, false) => {
            let staging = staging.keep();
            if let Err(error) = rename_project_init_noreplace(&staging, &options.directory) {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        }
        (true, true) => {
            publish_staged_project_into_existing(staging.path(), &options.directory)?;
            staging
                .close()
                .context("failed to discard private project initialization staging")?;
        }
        _ => bail!(
            "project destination changed while initialization was staged; no project files were published"
        ),
    }

    Ok(crate::InitReport {
        schema_version: crate::INIT_REPORT_SCHEMA_VERSION,
        status: "initialized",
        project: staged.project,
        project_kind: crate::InitProjectKind::RegistryProject,
        output: options.directory.clone(),
        source: crate::InitSource::Starter {
            id: staged.starter_id,
            release: staged.starter_release,
            content_digest: staged.starter_content_digest,
            content_state: "matches",
        },
        artifacts: crate::InitArtifacts {
            project_file: options.directory.join(PROJECT_FILE),
            editor_manifest: Some(options.directory.join(EDITOR_MANIFEST_PATH)),
        },
    })
}

fn preflight_project_init_destination(destination: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("failed to inspect project destination"),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::read_dir(destination)
            .context("failed to inspect project destination")?
            .next()
            .is_some()
    {
        bail!("project destination must be absent or an empty real directory");
    }
    Ok(true)
}

fn stage_registry_project_init(
    starter: &include_dir::Dir<'_>,
    selected_starter: ProjectStarter,
    staging: &Path,
) -> Result<StagedProjectInit> {
    copy_embedded_dir(starter, staging)?;
    let project = load_registry_project(staging, None)?;
    let provenance = project
        .project
        .starter
        .as_ref()
        .ok_or_else(|| anyhow!("embedded project starter is missing provenance"))?;
    if provenance.id != selected_starter.id() {
        bail!("embedded project starter provenance does not match the selected starter");
    }
    if provenance.content_digest != project.project_content_digest {
        bail!("embedded project starter content digest is invalid");
    }
    setup_registry_project_editor(&ProjectEditorSetupOptions {
        project_directory: staging.to_path_buf(),
    })?;
    Ok(StagedProjectInit {
        project: project.project.registry.id.clone(),
        starter_id: provenance.id.clone(),
        starter_release: provenance.release.clone(),
        starter_content_digest: provenance.content_digest.clone(),
    })
}

fn publish_staged_project_into_existing(source: &Path, destination: &Path) -> Result<()> {
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("failed to read staged project {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let target = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).with_context(|| {
            format!(
                "failed to inspect staged project path {}",
                source_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!("staged project contains a forbidden symlink");
        }
        if metadata.is_dir() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(&target).with_context(|| {
                format!("failed to create project directory {}", target.display())
            })?;
            publish_staged_project_into_existing(&source_path, &target)?;
        } else if metadata.is_file() {
            write_private_file(&target, &fs::read(&source_path)?).with_context(|| {
                format!("failed to publish staged project file {}", target.display())
            })?;
        } else {
            bail!("staged project contains an unsupported file type");
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_project_init_noreplace(source: &Path, destination: &Path) -> Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(std::io::Error::from)
    .context("failed to publish staged project without replacing an existing path")
}

#[cfg(windows)]
fn rename_project_init_noreplace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)
        .context("failed to publish staged project without replacing an existing path")
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", windows)))]
fn rename_project_init_noreplace(_source: &Path, _destination: &Path) -> Result<()> {
    bail!("atomic no-clobber project publication is unsupported on this platform")
}

#[cfg(test)]
mod project_init_staging_tests {
    use super::*;

    fn options(directory: PathBuf) -> ProjectInitOptions {
        ProjectInitOptions {
            starter: ProjectStarter::Http,
            directory,
        }
    }

    fn inject_late_editor_failure() {
        EDITOR_TEST_PUBLISH_FAILURE_AFTER.with(|remaining| remaining.set(Some(3)));
    }

    fn assert_no_staging_directories(parent: &Path) {
        assert!(
            fs::read_dir(parent)
                .expect("project parent reads")
                .all(|entry| !entry
                    .expect("project parent entry reads")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".registry-stack-init.transaction-")),
            "project initialization staging must be cleaned"
        );
    }

    #[test]
    fn late_editor_failure_leaves_absent_destination_untouched_and_retry_succeeds() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let destination = temporary.path().join("missing-parent/registry-project");
        inject_late_editor_failure();

        init_registry_project(&options(destination.clone()))
            .expect_err("late editor publication failure must fail init");
        assert!(!destination.exists());
        assert_no_staging_directories(destination.parent().expect("destination parent"));

        let report = init_registry_project(&options(destination.clone()))
            .expect("retry after staged editor failure succeeds");
        assert_eq!(report.status, "initialized");
        assert!(destination.join(PROJECT_FILE).is_file());
        assert!(destination.join(EDITOR_MANIFEST_PATH).is_file());
    }

    #[test]
    fn late_editor_failure_leaves_preexisting_empty_destination_untouched() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let destination = temporary.path().join("registry-project");
        fs::create_dir(&destination).expect("empty destination creates");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&destination, fs::Permissions::from_mode(0o750))
                .expect("destination mode sets");
        }
        inject_late_editor_failure();

        init_registry_project(&options(destination.clone()))
            .expect_err("late editor publication failure must fail init");
        assert!(destination.is_dir());
        assert!(fs::read_dir(&destination)
            .expect("destination reads")
            .next()
            .is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&destination)
                    .expect("destination metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
        }
        assert_no_staging_directories(temporary.path());
    }
}

pub fn test_registry_project(options: &ProjectTestOptions) -> Result<ProjectCommandReport> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    test_registry_project_with_context(options, &execution_context)
}

pub fn test_registry_project_with_context(
    options: &ProjectTestOptions,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    test_registry_project_selected_with_context(
        options,
        &ProjectTestSelection::default(),
        execution_context,
    )
}

pub fn test_registry_project_selected(
    options: &ProjectTestOptions,
    selection: &ProjectTestSelection,
) -> Result<ProjectCommandReport> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    test_registry_project_selected_with_context(options, selection, &execution_context)
}

pub fn test_registry_project_selected_with_context(
    options: &ProjectTestOptions,
    selection: &ProjectTestSelection,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    let loaded = load_registry_project(&options.project_directory, options.environment.as_deref())?;
    preflight_project_rhai_scripts(&loaded)?;
    let offline_environment = offline_fixture_environment(&loaded)?;
    validate_environment(
        &loaded.project,
        &loaded.integrations,
        &loaded.entities,
        &offline_environment,
    )?;
    let compiled =
        compile_project_for_environment(&loaded, "offline-fixture", &offline_environment, None)?;
    validate_generated_product_configs(&compiled)?;
    let (reports, generated_observations, call_budget_actual) =
        execute_all_fixtures_with_coverage_observations(
            &loaded,
            &compiled,
            selection.integration.as_deref(),
            selection.fixture.as_deref(),
            selection.trace,
            execution_context,
        )?;
    require_passing_fixtures(&reports)?;
    let fixture_coverage = if selection.integration.is_none() && selection.fixture.is_none() {
        Some(generate_fixture_coverage_report(
            &loaded,
            &reports,
            &generated_observations,
            call_budget_actual,
        )?)
    } else {
        None
    };
    Ok(ProjectCommandReport {
        schema_version: PROJECT_COMMAND_REPORT_SCHEMA_VERSION,
        status: "passed",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures: reports,
        semantic_changes: Vec::new(),
        baseline: "initial_without_baseline",
        output: None,
        semantic_impact: None,
        artifact_manifest: None,
        fixture_coverage,
        explanation: None,
    })
}

fn offline_fixture_environment(loaded: &LoadedRegistryProject) -> Result<EnvironmentDocument> {
    let requires_relay = project_requires_relay(&loaded.project);
    let requires_relay_consultation = project_requires_consultation_relay(&loaded.project);
    let mut integrations = BTreeMap::new();
    for (alias, integration) in &loaded.integrations {
        if matches!(
            integration.document.capability,
            CapabilityDeclaration::Snapshot { .. }
        ) {
            continue;
        }
        let credential_type = credential_interface(&integration.document).credential_type;
        let credential = match credential_type {
            CredentialType::None => None,
            CredentialType::Basic => Some(EnvironmentCredential {
                username: Some(SecretReference {
                    secret: "REGISTRY_PROJECT_FIXTURE_USERNAME".to_string(),
                }),
                password: Some(SecretReference {
                    secret: "REGISTRY_PROJECT_FIXTURE_PASSWORD".to_string(),
                }),
                token: None,
                client_id: None,
                client_secret: None,
                value: None,
                generation: 1,
            }),
            CredentialType::StaticBearer => Some(EnvironmentCredential {
                username: None,
                password: None,
                token: Some(SecretReference {
                    secret: "REGISTRY_PROJECT_FIXTURE_TOKEN".to_string(),
                }),
                client_id: None,
                client_secret: None,
                value: None,
                generation: 1,
            }),
            CredentialType::Oauth2ClientCredentials => Some(EnvironmentCredential {
                username: None,
                password: None,
                token: None,
                client_id: Some(SecretReference {
                    secret: "REGISTRY_PROJECT_FIXTURE_CLIENT_ID".to_string(),
                }),
                client_secret: Some(SecretReference {
                    secret: "REGISTRY_PROJECT_FIXTURE_CLIENT_SECRET".to_string(),
                }),
                value: None,
                generation: 1,
            }),
            CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
                Some(EnvironmentCredential {
                    username: None,
                    password: None,
                    token: None,
                    client_id: None,
                    client_secret: None,
                    value: Some(SecretReference {
                        secret: "REGISTRY_PROJECT_FIXTURE_API_KEY".to_string(),
                    }),
                    generation: 1,
                })
            }
        };
        let has_credential_destination = credential_type == CredentialType::Oauth2ClientCredentials;
        let has_verification_destination = has_authored_signed_dci(&integration.document);
        let credential_path = has_credential_destination
            .then(|| offline_oauth_path(integration))
            .transpose()?;
        let verification_path = has_verification_destination
            .then(|| offline_verification_path(integration))
            .transpose()?;
        integrations.insert(
            alias.clone(),
            EnvironmentIntegration {
                source: EnvironmentSourceBinding {
                    origin: format!("https://{alias}.fixture.invalid"),
                    allowed_private_cidrs: Vec::new(),
                    ca: None,
                    mtls: None,
                    credential,
                    oauth: has_credential_destination.then(|| PrivateEndpointBinding {
                        origin: format!("https://{alias}-credential.fixture.invalid"),
                        path: credential_path.expect("credential path was derived"),
                        allowed_private_cidrs: Vec::new(),
                        ca: None,
                        mtls: None,
                        generation: 1,
                    }),
                    jwks: has_verification_destination.then(|| PrivateEndpointBinding {
                        origin: format!("https://{alias}-verification.fixture.invalid"),
                        path: verification_path.expect("verification path was derived"),
                        allowed_private_cidrs: Vec::new(),
                        ca: None,
                        mtls: None,
                        generation: 1,
                    }),
                    rate: None,
                    concurrency: None,
                    timeout: None,
                },
            },
        );
    }
    let entities = loaded
        .entities
        .iter()
        .map(|(id, definition)| {
            (
                id.clone(),
                EnvironmentEntityBinding {
                    provider: RecordProvider::Csv {
                        path: PathBuf::from(format!("/var/lib/registry-fixtures/{id}.csv")),
                        header_row: Some(1),
                        delimiter: None,
                        quote: None,
                    },
                    columns: definition
                        .document
                        .schema
                        .properties
                        .keys()
                        .map(|field| (field.clone(), field.clone()))
                        .collect(),
                    source_revision: "offline-fixture".to_string(),
                    generation: "offline-fixture-1".to_string(),
                },
            )
        })
        .collect();
    Ok(EnvironmentDocument {
        version: 1,
        development: None,
        integrations,
        entities,
        relay: requires_relay.then(|| RelayBinding {
            origin: "https://relay.fixture.invalid".to_string(),
            issuer: "https://workload.fixture.invalid".to_string(),
            jwks_url: "https://workload.fixture.invalid/.well-known/jwks.json".to_string(),
            audience: "registry-relay".to_string(),
            allowed_clients: vec!["registry-project-fixture-client".to_string()],
            consultation: requires_relay_consultation.then(|| RelayConsultationBinding {
                client_id: "registry-project-fixture-consultation-client".to_string(),
                principal_id: "registry-project-fixture-principal".to_string(),
            }),
            local_api_keys: None,
        }),
        relay_state: None,
        deployment: DeploymentBinding {
            profile: DeploymentProfile::Local,
            relay: requires_relay.then(|| ServiceBinding {
                service: "registry-project-fixture-relay".to_string(),
            }),
        },
    })
}

fn offline_oauth_path(integration: &LoadedIntegration) -> Result<String> {
    offline_private_path(integration, "OAuth", |request| {
        request.method == ReadMethod::Post
            && request.body.as_ref().is_some_and(|body| {
                body.as_object().is_some_and(|body| {
                    body.len() == 1
                        && body.get("grant_type").and_then(Value::as_str)
                            == Some("client_credentials")
                })
            })
    })
}

fn offline_verification_path(integration: &LoadedIntegration) -> Result<String> {
    offline_private_path(integration, "verification", |request| {
        request.method == ReadMethod::Get && request.body.is_none()
    })
}

fn offline_private_path(
    integration: &LoadedIntegration,
    kind: &str,
    matches: impl Fn(&FixtureRequestExpectation) -> bool,
) -> Result<String> {
    let paths = integration
        .fixtures
        .iter()
        .flat_map(|(_, fixture)| &fixture.interactions)
        .filter(|interaction| matches(&interaction.expect))
        .map(|interaction| interaction.expect.path.as_str())
        .collect::<BTreeSet<_>>();
    if paths.len() != 1 {
        bail!("offline fixtures must prove one consistent {kind} request path");
    }
    Ok(paths
        .into_iter()
        .next()
        .expect("one private path was checked")
        .to_owned())
}

pub fn check_registry_project(options: &ProjectCheckOptions) -> Result<ProjectCommandReport> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    check_registry_project_with_context(options, &execution_context)
}

/// Run the same offline check while also selecting directly authored,
/// non-secret scalars for explicit trusted-local human review.
///
/// The additional values are not part of the portable command report and this
/// function must only back the human-only `--show-authored-values` CLI path.
pub fn check_registry_project_with_trusted_local_authored_values(
    options: &ProjectCheckOptions,
) -> Result<ProjectTrustedLocalCheck> {
    if !options.explain {
        bail!("trusted-local authored values require an explanation");
    }
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    check_registry_project_internal(options, &execution_context, true)
}

pub fn check_registry_project_with_context(
    options: &ProjectCheckOptions,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    check_registry_project_internal(options, execution_context, false).map(|result| result.report)
}

fn check_registry_project_internal(
    options: &ProjectCheckOptions,
    execution_context: &ProjectExecutionContext,
    include_trusted_local_authored_values: bool,
) -> Result<ProjectTrustedLocalCheck> {
    validate_baseline_pair(options.against.as_deref(), options.anchor.as_deref())?;
    let diagnostics = collect_project_authoring_diagnostics(
        &options.project_directory,
        options.environment.as_str(),
    );
    if !diagnostics.diagnostics.is_empty() {
        return Err(anyhow::Error::new(diagnostics));
    }
    let loaded = load_registry_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )
    .map_err(|_| {
        anyhow::Error::new(finalized_diagnostics(vec![invalid_diagnostic(
            "registryctl.authoring.project.invalid",
            PROJECT_FILE,
            None,
            "The project could not be loaded safely after authoring diagnostics.",
            "Keep the project tree stable, then run project check again.",
            Some(PROJECT_SCHEMA_HINT),
        )]))
    })?;
    preflight_project_rhai_scripts(&loaded)?;
    let baselines = load_verified_approved_baseline_set(
        ApprovedBaselineSetPaths::legacy(options.against.as_deref(), options.anchor.as_deref()),
        &loaded,
        BaselineSetCompleteness::AnyVerifiedProduct,
    )?;
    let compiled = compile_project(&loaded, (!baselines.is_empty()).then_some(&baselines))?;
    validate_generated_product_configs(&compiled)?;
    validate_project_workbook_inputs(&loaded, &compiled)?;
    let (fixtures, generated_observations, call_budget_actual) =
        execute_all_fixtures_with_coverage_observations(
            &loaded,
            &compiled,
            None,
            None,
            false,
            execution_context,
        )?;
    require_passing_fixtures(&fixtures)?;
    let fixture_coverage = generate_fixture_coverage_report(
        &loaded,
        &fixtures,
        &generated_observations,
        call_budget_actual,
    )?;
    let authored_values = if include_trusted_local_authored_values {
        trusted_local_authored_values(&loaded, &compiled.explanation)?
    } else {
        Vec::new()
    };
    let report = ProjectCommandReport {
        schema_version: PROJECT_COMMAND_REPORT_SCHEMA_VERSION,
        status: "valid",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        baseline: if !baselines.is_empty() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: None,
        semantic_impact: Some(compiled.semantic_impact),
        artifact_manifest: None,
        fixture_coverage: Some(fixture_coverage),
        explanation: options.explain.then_some(compiled.explanation),
    };
    Ok(ProjectTrustedLocalCheck {
        report,
        authored_values,
    })
}

/// Verify the selected environment's locally available secret and file posture,
/// including production-equivalent validation of project-authored workbooks.
///
/// This command is intentionally offline. It performs no fixture execution,
/// build publication, network access, or runtime source contact.
pub fn preflight_registry_project(
    options: &ProjectPreflightOptions,
) -> Result<ProjectPreflightReportV1> {
    let diagnostics = collect_project_authoring_diagnostics(
        &options.project_directory,
        options.environment.as_str(),
    );
    if !diagnostics.diagnostics.is_empty() {
        return Err(anyhow::Error::new(diagnostics));
    }
    let loaded = load_registry_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    let compiled = compile_project(&loaded, None)?;
    validate_generated_product_configs(&compiled)?;
    validate_project_workbook_inputs(&loaded, &compiled)?;
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("preflight requires an explicit environment"))?;
    let mut input = offline_preflight_input(&loaded, environment, &options.environment)?;
    if project_requires_relay(&loaded.project) {
        input.require_product(PreflightProduct::RegistryRelay);
        input.record_product_validator_available(PreflightProduct::RegistryRelay);
    }
    Ok(run_offline_preflight(input))
}

pub fn inspect_project_capabilities(
    options: &ProjectCapabilityOptions,
) -> Result<ProjectCapabilityInventoryReportV1> {
    let loaded = load_registry_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("capability inventory requires an explicit environment"))?;
    let mut input = CapabilityInventoryInput::new();

    for (capability, state, evidence) in capability_inventory::COMPILED_CAPABILITY_RELEASE_FACTS {
        input.record_installed_capability(capability, state, evidence)?;
    }

    for (component, state, evidence) in [
        (
            SupportComponent::HttpSourceWorker,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RhaiScriptWorker,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::SnapshotMaterializationWorker,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RhaiXwProtocolHelper,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryRelayProduct,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryRelayValidator,
            SupportState::Available,
            SupportEvidence::LinkedProductValidator,
        ),
        (
            SupportComponent::ProjectAuthoringSchema,
            SupportState::Available,
            SupportEvidence::EmbeddedSchema,
        ),
        (
            SupportComponent::RegistryRelayConfigSchema,
            SupportState::Available,
            SupportEvidence::EmbeddedSchema,
        ),
        (
            SupportComponent::RegistryctlDistribution,
            SupportState::Available,
            SupportEvidence::ReleaseMetadata,
        ),
        (
            SupportComponent::RegistryRelayImage,
            SupportState::NotEvaluated,
            SupportEvidence::NoEvidence,
        ),
    ] {
        input.record_support(component, state, evidence)?;
    }

    let mut declarations = BTreeSet::new();
    let mut enabled = BTreeSet::new();
    let mut integration_capabilities = BTreeMap::new();
    for (integration_id, integration) in &loaded.integrations {
        let capability = match &integration.document.capability {
            CapabilityDeclaration::Http { .. } => CapabilityId::SourceHttp,
            CapabilityDeclaration::Script { .. } => CapabilityId::SourceScript,
            CapabilityDeclaration::Snapshot { .. } => CapabilityId::SourceSnapshot,
        };
        declarations.insert(capability);
        integration_capabilities.insert(integration_id.as_str(), capability);
        let is_enabled = match &integration.document.capability {
            CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
                environment.integrations.contains_key(integration_id)
            }
            CapabilityDeclaration::Snapshot { snapshot } => {
                environment.entities.contains_key(&snapshot.entity)
            }
        };
        if is_enabled {
            enabled.insert(capability);
        }
    }
    if project_requires_relay(&loaded.project) {
        declarations.insert(CapabilityId::RegistryRelayProduct);
    }
    if environment.deployment.relay.is_some() {
        enabled.insert(CapabilityId::RegistryRelayProduct);
    }
    for capability in declarations {
        input.record_project_declaration(capability)?;
    }
    for capability in enabled {
        input.record_environment_enablement(capability)?;
    }

    let mut usage = BTreeMap::<CapabilityId, CapabilityUsageCounts>::new();
    for service in loaded.project.services.values() {
        let mut service_capabilities = BTreeSet::new();
        for consultation in service.consultations.values() {
            if let Some(capability) =
                integration_capabilities.get(consultation.integration.as_str())
            {
                service_capabilities.insert(*capability);
                let counts = usage.entry(*capability).or_default();
                counts.consultations = counts.consultations.checked_add(1).ok_or_else(|| {
                    anyhow!("capability consultation count exceeds the report cap")
                })?;
            }
        }
        for capability in service_capabilities {
            let counts = usage.entry(capability).or_default();
            counts.services = counts
                .services
                .checked_add(1)
                .ok_or_else(|| anyhow!("capability service count exceeds the report cap"))?;
        }
        let product = CapabilityId::RegistryRelayProduct;
        let counts = usage.entry(product).or_default();
        counts.services = counts
            .services
            .checked_add(1)
            .ok_or_else(|| anyhow!("product service count exceeds the report cap"))?;
        counts.consultations = counts
            .consultations
            .checked_add(u32::try_from(service.consultations.len())?)
            .ok_or_else(|| anyhow!("product consultation count exceeds the report cap"))?;
    }
    if let Some(script_usage) = usage.get(&CapabilityId::SourceScript).copied() {
        usage.insert(CapabilityId::RhaiRuntime, script_usage);
        usage.insert(CapabilityId::RhaiAbi, script_usage);
    }
    for (capability, counts) in usage {
        if counts != CapabilityUsageCounts::default() {
            input.record_usage(capability, counts)?;
        }
    }
    build_capability_inventory(input).map_err(anyhow::Error::from)
}

fn offline_preflight_input(
    loaded: &LoadedRegistryProject,
    environment: &EnvironmentDocument,
    environment_name: &str,
) -> Result<OfflinePreflightInput> {
    let environment_file = format!("environments/{environment_name}.yaml");
    let root = PreflightFieldAddress::new(PROJECT_FILE, "")?;
    let environment_root = PreflightFieldAddress::new(&environment_file, "")?;
    let mut input =
        OfflinePreflightInput::new(&loaded.project.registry.id, environment_name.to_owned())?;
    for capability in [
        PreflightStaticCapability::ProjectModel,
        PreflightStaticCapability::EnvironmentCompleteness,
        PreflightStaticCapability::OriginRelationships,
        PreflightStaticCapability::NonWideningBounds,
    ] {
        input.record_static_validation(capability, [root.clone(), environment_root.clone()]);
    }

    for (integration_id, integration) in &environment.integrations {
        let integration = &integration.source;
        let prefix = format!(
            "/integrations/{}/source",
            escape_explanation_pointer_segment(integration_id)
        );
        if let Some(credential) = &integration.credential {
            for (reference, consumer, field) in [
                (
                    credential.username.as_ref(),
                    PreflightSecretConsumer::SourceBasicUsername,
                    "username",
                ),
                (
                    credential.password.as_ref(),
                    PreflightSecretConsumer::SourceBasicPassword,
                    "password",
                ),
                (
                    credential.token.as_ref(),
                    PreflightSecretConsumer::SourceBearerToken,
                    "token",
                ),
                (
                    credential.client_id.as_ref(),
                    PreflightSecretConsumer::SourceOauthClientId,
                    "client_id",
                ),
                (
                    credential.client_secret.as_ref(),
                    PreflightSecretConsumer::SourceOauthClientSecret,
                    "client_secret",
                ),
                (
                    credential.value.as_ref(),
                    PreflightSecretConsumer::SourceApiKeyValue,
                    "value",
                ),
            ] {
                if let Some(reference) = reference {
                    add_preflight_secret(
                        &mut input,
                        &environment_file,
                        &format!("{prefix}/credential/{field}/secret"),
                        reference,
                        consumer,
                    )?;
                }
            }
        }
        add_preflight_transport_files(
            &mut input,
            &environment_file,
            &prefix,
            integration.ca.as_ref(),
            integration.mtls.as_ref(),
            PreflightRuntimeFileKind::SourceCa,
            PreflightRuntimeFileKind::SourceMtlsCertificate,
            PreflightSecretConsumer::SourceMtlsPrivateKey,
        )?;
        for (name, endpoint, ca_kind, certificate_kind, private_key_consumer) in [
            (
                "oauth",
                integration.oauth.as_ref(),
                PreflightRuntimeFileKind::SourceOauthCa,
                PreflightRuntimeFileKind::SourceOauthMtlsCertificate,
                PreflightSecretConsumer::SourceOauthMtlsPrivateKey,
            ),
            (
                "jwks",
                integration.jwks.as_ref(),
                PreflightRuntimeFileKind::SourceJwksCa,
                PreflightRuntimeFileKind::SourceJwksMtlsCertificate,
                PreflightSecretConsumer::SourceJwksMtlsPrivateKey,
            ),
        ] {
            if let Some(endpoint) = endpoint {
                add_preflight_transport_files(
                    &mut input,
                    &environment_file,
                    &format!("{prefix}/{name}"),
                    endpoint.ca.as_ref(),
                    endpoint.mtls.as_ref(),
                    ca_kind,
                    certificate_kind,
                    private_key_consumer,
                )?;
            }
        }
    }

    for (entity_id, entity) in &environment.entities {
        let entity_prefix = format!(
            "/entities/{}/provider",
            escape_explanation_pointer_segment(entity_id)
        );
        match &entity.provider {
            RecordProvider::Csv { path, .. } => add_preflight_runtime_file(
                &mut input,
                &environment_file,
                &format!("{entity_prefix}/path"),
                path,
                PreflightRuntimeFileKind::EntityCsv,
            )?,
            RecordProvider::Xlsx { project_file, .. } => add_preflight_runtime_file(
                &mut input,
                &environment_file,
                &format!("{entity_prefix}/project_file"),
                &loaded.root.join(project_file),
                PreflightRuntimeFileKind::EntityXlsx,
            )?,
            RecordProvider::Parquet { path } => add_preflight_runtime_file(
                &mut input,
                &environment_file,
                &format!("{entity_prefix}/path"),
                path,
                PreflightRuntimeFileKind::EntityParquet,
            )?,
            RecordProvider::Postgres { connection, .. } => add_preflight_secret(
                &mut input,
                &environment_file,
                &format!("{entity_prefix}/connection/secret"),
                connection,
                PreflightSecretConsumer::EntityPostgresConnection,
            )?,
        }
    }
    if let Some(binding) = &environment.relay_state {
        add_preflight_runtime_file(
            &mut input,
            &environment_file,
            "/relay_state/postgresql/root_certificate_path",
            &binding.postgresql.root_certificate_path,
            PreflightRuntimeFileKind::RelayStateRootCertificate,
        )?;
    }
    Ok(input)
}

// Keeping the paired CA and mTLS classifications explicit at each call site
// makes ownership mistakes visible during review.
#[allow(clippy::too_many_arguments)]
fn add_preflight_transport_files(
    input: &mut OfflinePreflightInput,
    environment_file: &str,
    prefix: &str,
    ca: Option<&CertificateAuthorityBinding>,
    mtls: Option<&MutualTlsBinding>,
    ca_kind: PreflightRuntimeFileKind,
    certificate_kind: PreflightRuntimeFileKind,
    private_key_consumer: PreflightSecretConsumer,
) -> Result<()> {
    if let Some(ca) = ca {
        add_preflight_runtime_file(
            input,
            environment_file,
            &format!("{prefix}/ca/file"),
            &ca.file,
            ca_kind,
        )?;
    }
    if let Some(mtls) = mtls {
        add_preflight_runtime_file(
            input,
            environment_file,
            &format!("{prefix}/mtls/certificate_file"),
            &mtls.certificate_file,
            certificate_kind,
        )?;
        add_preflight_secret(
            input,
            environment_file,
            &format!("{prefix}/mtls/private_key/secret"),
            &mtls.private_key,
            private_key_consumer,
        )?;
    }
    Ok(())
}

fn add_preflight_secret(
    input: &mut OfflinePreflightInput,
    file: &str,
    pointer: &str,
    reference: &SecretReference,
    consumer: PreflightSecretConsumer,
) -> Result<()> {
    input
        .add_secret_reference(
            &reference.secret,
            consumer,
            PreflightFieldAddress::new(file, pointer)?,
        )
        .map_err(anyhow::Error::from)
}

fn add_preflight_runtime_file(
    input: &mut OfflinePreflightInput,
    file: &str,
    pointer: &str,
    path: &Path,
    kind: PreflightRuntimeFileKind,
) -> Result<()> {
    input
        .add_runtime_file(path, kind, PreflightFieldAddress::new(file, pointer)?)
        .map_err(anyhow::Error::from)
}

pub fn build_registry_project(options: &ProjectBuildOptions) -> Result<ProjectCommandReport> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    build_registry_project_with_context(options, &execution_context)
}

pub fn build_registry_project_with_baselines(
    options: &ProjectBuildOptions,
    baselines: &ProjectBuildBaselineSetOptions,
) -> Result<ProjectCommandReport> {
    let execution_context = ProjectExecutionContext::for_current_executable()?;
    build_registry_project_with_baselines_and_context(options, baselines, &execution_context)
}

pub fn build_registry_project_with_context(
    options: &ProjectBuildOptions,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    build_registry_project_inner(options, None, execution_context)
}

pub fn build_registry_project_with_baselines_and_context(
    options: &ProjectBuildOptions,
    baselines: &ProjectBuildBaselineSetOptions,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    build_registry_project_inner(options, Some(baselines), execution_context)
}

fn build_registry_project_inner(
    options: &ProjectBuildOptions,
    baseline_options: Option<&ProjectBuildBaselineSetOptions>,
    execution_context: &ProjectExecutionContext,
) -> Result<ProjectCommandReport> {
    let baseline_paths = ApprovedBaselineSetPaths::build(options, baseline_options);
    validate_approved_baseline_set_paths(baseline_paths)?;
    let loaded = load_registry_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    let signing_input_identities = governed_signing_input_identities(&loaded)?;
    preflight_project_rhai_scripts(&loaded)?;
    let baselines = load_verified_approved_baseline_set(
        baseline_paths,
        &loaded,
        BaselineSetCompleteness::CompleteTopologyWhenPresent,
    )
    .map_err(|_| anyhow!("could not establish verified build baselines"))?;
    let compiled = compile_project(&loaded, (!baselines.is_empty()).then_some(&baselines))?;
    validate_generated_product_configs(&compiled)?;
    let artifact_inputs = validate_project_workbook_inputs(&loaded, &compiled)?;
    let (fixtures, generated_observations, call_budget_actual) =
        execute_all_fixtures_with_coverage_observations(
            &loaded,
            &compiled,
            None,
            None,
            false,
            execution_context,
        )?;
    require_passing_fixtures(&fixtures)?;
    let fixture_coverage = generate_fixture_coverage_report(
        &loaded,
        &fixtures,
        &generated_observations,
        call_budget_actual,
    )?;
    let output = loaded
        .root
        .join(BUILD_ROOT)
        .join(options.environment.as_str());
    let artifact_manifest = write_compiled_project(
        &loaded.root,
        &output,
        &compiled,
        &loaded.project.registry.id,
        &options.environment,
        &artifact_inputs,
        &signing_input_identities,
    )?;
    let reported_output = ProjectRelativePath::new(format!("{BUILD_ROOT}/{}", options.environment))
        .map_err(|error| anyhow!("invalid project-relative build output path: {error}"))?;
    Ok(ProjectCommandReport {
        schema_version: PROJECT_COMMAND_REPORT_SCHEMA_VERSION,
        status: "built",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        baseline: if !baselines.is_empty() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: Some(reported_output.as_str().to_string()),
        semantic_impact: Some(compiled.semantic_impact),
        artifact_manifest: Some(artifact_manifest),
        fixture_coverage: Some(fixture_coverage),
        explanation: None,
    })
}

fn require_passing_fixtures(fixtures: &[FixtureReport]) -> Result<()> {
    let failing = fixtures
        .iter()
        .filter(|fixture| !fixture.passed)
        .map(|fixture| {
            format!(
                "{}.{} ({})",
                fixture.integration,
                fixture.fixture,
                fixture.failure.as_deref().unwrap_or("unknown")
            )
        })
        .collect::<Vec<_>>();
    if !failing.is_empty() {
        bail!(
            "project integration fixtures failed: {}",
            failing.join(", ")
        );
    }
    Ok(())
}
