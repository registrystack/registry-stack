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
            bruno_collection: None,
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
    if options.live && options.environment.is_none() {
        bail!("live project tests require an explicit non-production --environment");
    }
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
    let (mut reports, generated_observations, request_observations, call_budget_actual) =
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
            &request_observations,
            call_budget_actual,
        )?)
    } else {
        None
    };
    if options.live {
        reports.push(execute_governed_live_test(&loaded)?);
    }
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
    let (requires_relay, requires_notary) = project_product_topology(&loaded.project);
    let requires_issuance = project_issues_credentials(&loaded.project);
    let requires_notary_relay = project_requires_notary_relay(&loaded.project);
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
    let callers = loaded
        .project
        .services
        .iter()
        .filter(|(_, service)| service.kind == ServiceKind::Evidence)
        .map(|(service_id, service)| {
            (
                service_id.clone(),
                CallerBinding {
                    api_key_fingerprint: SecretReference {
                        secret: "REGISTRY_PROJECT_FIXTURE_API_KEY_HASH".to_string(),
                    },
                    scopes: service.access.scopes.clone(),
                },
            )
        })
        .collect();
    Ok(EnvironmentDocument {
        version: 1,
        integrations,
        entities,
        issuance: requires_issuance.then(|| IssuanceBinding {
            issuer: "did:web:notary.fixture.invalid".to_string(),
            signing_key: SecretReference {
                secret: "REGISTRY_PROJECT_FIXTURE_ISSUER_JWK".to_string(),
            },
            signing_kid: "offline-fixture-key".to_string(),
            generation: 1,
            algorithm: IssuanceSigningAlgorithm::default(),
        }),
        callers: if requires_notary {
            callers
        } else {
            BTreeMap::new()
        },
        relay: requires_relay.then(|| RelayBinding {
            origin: "https://relay.fixture.invalid".to_string(),
            issuer: "https://workload.fixture.invalid".to_string(),
            jwks_url: "https://workload.fixture.invalid/.well-known/jwks.json".to_string(),
            audience: "registry-relay".to_string(),
            allowed_clients: vec!["registry-project-fixture-client".to_string()],
            local_api_keys: None,
        }),
        notary_relay: requires_notary_relay.then(|| NotaryRelayBinding {
            base_url: "https://relay.fixture.invalid".to_string(),
            workload_client_id: "registry-project-fixture-notary".to_string(),
            token_file: PathBuf::from("/run/secrets/offline-fixture-token"),
        }),
        relay_state: None,
        notary_state: None,
        notary_cel: None,
        oid4vci: None,
        deployment: DeploymentBinding {
            profile: DeploymentProfile::Local,
            relay: requires_relay.then(|| ServiceBinding {
                service: "registry-project-fixture-relay".to_string(),
            }),
            notary: requires_notary.then(|| ServiceBinding {
                service: "registry-project-fixture-notary".to_string(),
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

// A remote candidate can have a small NTP offset from the operator host. Thirty
// seconds accommodates that offset without accepting evidence outside this
// single governed request.
const GOVERNED_LIVE_REMOTE_CLOCK_SKEW: time::Duration = time::Duration::seconds(30);

#[derive(Clone, Copy)]
struct GovernedLiveValidationWindow {
    request_started_at: OffsetDateTime,
    response_received_at: OffsetDateTime,
}

fn execute_governed_live_test(loaded: &LoadedRegistryProject) -> Result<FixtureReport> {
    let environment = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("live project tests require an environment"))?;
    let deployment_profile = loaded
        .environment
        .as_ref()
        .map(|environment| environment.deployment.profile);
    if governed_live_environment_is_production(environment, deployment_profile) {
        bail!("live project tests refuse production-classified environment names or profiles");
    }
    let origin = std::env::var("REGISTRY_STACK_LIVE_NOTARY_ORIGIN")
        .context("live Notary origin is absent from the process environment")?;
    let origin = validate_live_notary_origin(&origin)?;
    let api_key = std::env::var("REGISTRY_STACK_LIVE_NOTARY_API_KEY")
        .context("live Notary API key is absent from the process environment")?;
    if api_key.len() < 32 || api_key.len() > 4096 || api_key.chars().any(char::is_control) {
        bail!("live Notary API key has an invalid bounded shape");
    }
    let request_path = std::env::var_os("REGISTRY_STACK_LIVE_REQUEST_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("live request file is absent from the process environment"))?;
    let request_bytes = read_bounded_external_request(&request_path)?;
    let request = parse_json_strict(&request_bytes).context("live request is not strict JSON")?;
    let prepared_request = prepare_governed_live_request(loaded, &request)?;
    validate_live_relay_readiness(&origin)?;
    let expected_path = std::env::var_os("REGISTRY_STACK_LIVE_EXPECTED_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow!("live expected-result file is absent from the process environment")
        })?;
    let expected_bytes = read_bounded_external_request(&expected_path)?;
    let expected = parse_json_strict(&expected_bytes)
        .context("live expected-result file is not strict JSON")?;
    let endpoint = origin
        .join("v1/evaluations")
        .map_err(|_| anyhow!("failed to construct the governed Notary endpoint"))?;
    let evaluation_request = governed_live_evaluation_request(&endpoint, &api_key);
    let request_started_at = OffsetDateTime::now_utc();
    let response = evaluation_request
        .send_bytes(&prepared_request.body)
        .map_err(|_| anyhow!("governed Notary evaluation failed"))?;
    let mut response_bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LIVE_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_bytes)
        .context("failed to read the governed Notary response")?;
    let response_received_at = OffsetDateTime::now_utc();
    if response_bytes.len() as u64 > MAX_LIVE_RESPONSE_BYTES {
        bail!("governed Notary response exceeded the configured bound");
    }
    let response = parse_json_strict(&response_bytes)
        .context("governed Notary response was not strict JSON")?;
    let returned_claims = validate_live_response(
        &response,
        &prepared_request.validated,
        &expected,
        GovernedLiveValidationWindow {
            request_started_at,
            response_received_at,
        },
    )?;
    Ok(governed_live_fixture_report(returned_claims))
}

fn governed_live_environment_is_production(
    environment: &str,
    deployment_profile: Option<DeploymentProfile>,
) -> bool {
    environment
        .split(['-', '_', '.'])
        .any(|segment| matches!(segment, "prod" | "production"))
        || matches!(
            deployment_profile,
            Some(DeploymentProfile::Production | DeploymentProfile::EvidenceGrade)
        )
}

fn governed_live_evaluation_request(endpoint: &url::Url, api_key: &str) -> ureq::Request {
    ureq::post(endpoint.as_str())
        .set("content-type", "application/json")
        .set("accept", registry_notary_core::FORMAT_CLAIM_RESULT_JSON)
        .set("x-api-key", api_key)
}

fn governed_live_fixture_report(returned_claims: Vec<String>) -> FixtureReport {
    FixtureReport {
        integration: "governed-notary-relay".to_string(),
        fixture: "live-evaluation".to_string(),
        inputs: Vec::new(),
        calls: vec!["notary-evaluation".to_string()],
        outputs: Vec::new(),
        claims: returned_claims,
        // Claim expectations prove disclosed values, not the source-level
        // match or no-match outcome that produced them.
        outcome: None,
        expected_error: None,
        source_access: None,
        passed: true,
        failure: None,
    }
}

fn validate_live_relay_readiness(origin: &url::Url) -> Result<()> {
    let endpoint = origin
        .join("ready")
        .map_err(|_| anyhow!("failed to construct the Notary readiness endpoint"))?;
    let response = ureq::get(endpoint.as_str())
        .set("accept", "application/json")
        .call()
        .map_err(|_| anyhow!("governed Notary readiness check failed"))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LIVE_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read governed Notary readiness")?;
    if bytes.len() as u64 > MAX_LIVE_RESPONSE_BYTES {
        bail!("governed Notary readiness response exceeded the configured bound");
    }
    let readiness = parse_json_strict(&bytes)
        .context("governed Notary readiness response was not strict JSON")?;
    let relay = readiness
        .pointer("/checks/relay")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("governed Notary readiness lacks the Relay dependency check"))?;
    let total = relay
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("governed Notary Relay readiness total is invalid"))?;
    let ok = relay
        .get("ok")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("governed Notary Relay readiness result is invalid"))?;
    if total == 0 || ok != total {
        bail!("governed Notary has no fully ready Relay-backed consultation dependency");
    }
    Ok(())
}

fn validate_live_response(
    response: &Value,
    request: &ValidatedLiveRequest,
    expected: &Value,
    validation_window: GovernedLiveValidationWindow,
) -> Result<Vec<String>> {
    let object = response
        .as_object()
        .ok_or_else(|| anyhow!("governed Notary response must be an object"))?;
    if object.len() != 1 || !object.contains_key("results") {
        bail!("governed Notary response has an unexpected top-level field");
    }
    let results = object["results"]
        .as_array()
        .ok_or_else(|| anyhow!("governed Notary response results must be an array"))?;
    if results.len() != request.claims.len() {
        bail!("governed Notary response did not return every requested claim exactly once");
    }
    let requested = request
        .claims
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("claims"))
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("live expected-result file must contain only a claims object"))?;
    if expected.keys().map(String::as_str).collect::<BTreeSet<_>>() != requested {
        bail!("live expected-result claims do not exactly match the governed request");
    }
    let mut returned = BTreeSet::new();
    let mut evaluation_id = None;
    let mut target_ref = None;
    let mut requester_ref = None;
    for result in results {
        let result_object = result
            .as_object()
            .ok_or_else(|| anyhow!("governed Notary result must be an object"))?;
        validate_live_result_raw_schema(result, result_object)?;
        let result_view: registry_notary_core::ClaimResultView =
            serde_json::from_value(result.clone()).map_err(|_| {
                anyhow!(
                    "governed Notary result does not match the closed public claim-result schema"
                )
            })?;
        if result_view.provenance.schema_version
            != registry_notary_core::CLAIM_PROVENANCE_SCHEMA_VERSION
            || result_view.provenance.generated_by.entry_type
                != registry_notary_core::PROVENANCE_GENERATED_BY_CLAIM_EVALUATION
        {
            bail!(
                "governed Notary result provenance constants do not match the closed public claim-result schema"
            );
        }
        let generated_by = &result_view.provenance.generated_by;
        if generated_by.evaluation_id != result_view.evaluation_id
            || generated_by.claim_id != result_view.claim_id
            || generated_by.claim_version != result_view.claim_version
        {
            bail!("governed Notary result provenance does not identify the returned claim result");
        }
        if generated_by.service_id != request.notary_service_id {
            bail!(
                "governed Notary result provenance does not identify the selected Notary service"
            );
        }
        if generated_by.policy_id.is_some()
            || generated_by.policy_version.is_some()
            || generated_by.policy_hash.is_some()
        {
            bail!("governed Notary API-key result carries unexpected named policy provenance");
        }
        if evaluation_id
            .as_ref()
            .is_some_and(|evaluation_id| evaluation_id != &result_view.evaluation_id)
        {
            bail!("governed Notary response combines results from different evaluations");
        }
        evaluation_id.get_or_insert_with(|| result_view.evaluation_id.clone());
        if result_view.format != registry_notary_core::FORMAT_CLAIM_RESULT_JSON {
            bail!("governed Notary result has an invalid claim-result format");
        }
        validate_live_result_timestamps(&result_view, validation_window)?;
        if !result_view.provenance.derived_from.is_empty() {
            bail!("governed Notary result provenance derived_from must remain empty");
        }
        validate_live_result_reference_handles(&result_view)?;
        let result_target_ref = result_object
            .get("target_ref")
            .ok_or_else(|| anyhow!("governed Notary result lacks its target reference"))?;
        if target_ref
            .as_ref()
            .is_some_and(|target_ref| target_ref != result_target_ref)
        {
            bail!("governed Notary response combines inconsistent evaluation references");
        }
        target_ref.get_or_insert_with(|| result_target_ref.clone());
        let result_requester_ref = result_object.get("requester_ref").cloned();
        if requester_ref
            .as_ref()
            .is_some_and(|requester_ref| requester_ref != &result_requester_ref)
        {
            bail!("governed Notary response combines inconsistent evaluation references");
        }
        requester_ref.get_or_insert(result_requester_ref);
        let claim_id = result_view.claim_id.as_str();
        if !requested.contains(claim_id) || !returned.insert(claim_id.to_string()) {
            bail!("governed Notary response contains an unknown or duplicate claim result");
        }
        if request.claim_versions.get(claim_id).map(String::as_str)
            != Some(result_view.claim_version.as_str())
        {
            bail!("governed Notary result claim version does not match the authored project");
        }
        if result_view.subject_type != request.subject_type {
            bail!("governed Notary result subject type does not match the authored project");
        }
        let expected_result = expected[claim_id]
            .as_object()
            .ok_or_else(|| anyhow!("live expected claim result must be an object"))?;
        let expected_keys = expected_result
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if expected_keys != BTreeSet::from(["disclosure", "satisfied", "value"])
            && expected_keys
                != BTreeSet::from(["disclosure", "redacted_fields", "satisfied", "value"])
        {
            bail!(
                "live expected claim result must contain value, satisfied, disclosure, and optional redacted_fields"
            );
        }
        validate_live_result_redaction(
            &result_view,
            expected_result.get("redacted_fields"),
            expected_result.get("disclosure"),
        )?;
        for field in ["value", "satisfied", "disclosure"] {
            if result_object.get(field) != expected_result.get(field) {
                bail!("governed Notary disclosed claim result did not match the expected fixture");
            }
        }
        if result_view.provenance.used.relay_consultation_count == 0 {
            bail!("governed Notary result lacks source-backed provenance");
        }
    }
    Ok(returned.into_iter().collect())
}

fn validate_live_result_timestamps(
    result: &registry_notary_core::ClaimResultView,
    validation_window: GovernedLiveValidationWindow,
) -> Result<()> {
    let issued_at = OffsetDateTime::parse(&result.issued_at, &Rfc3339).map_err(|_| {
        anyhow!("governed Notary result timestamps do not match the public date-time schema")
    })?;
    let expires_at = result
        .expires_at
        .as_deref()
        .map(|expires_at| {
            OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
                anyhow!(
                    "governed Notary result timestamps do not match the public date-time schema"
                )
            })
        })
        .transpose()?;
    if validation_window.response_received_at < validation_window.request_started_at {
        bail!("governed Notary validation window is invalid");
    }
    let earliest_issued_at = validation_window.request_started_at - GOVERNED_LIVE_REMOTE_CLOCK_SKEW;
    let latest_issued_at = validation_window.response_received_at + GOVERNED_LIVE_REMOTE_CLOCK_SKEW;
    if issued_at < earliest_issued_at || issued_at > latest_issued_at {
        bail!("governed Notary result timestamps do not bind to the current live evaluation");
    }
    if expires_at.is_some_and(|expires_at| {
        expires_at <= validation_window.response_received_at || expires_at <= issued_at
    }) {
        bail!("governed Notary result timestamps do not bind to the current live evaluation");
    }
    Ok(())
}

// These properties are optional in the public OpenAPI schema, but their types
// exclude null when present. `expires_at` is intentionally not listed because
// the public schema requires that key and permits an explicit null.
const LIVE_RESULT_OPTIONAL_NON_NULL_PATHS: &[&str] = &[
    "/redacted_fields",
    "/requester_ref",
    "/requester_ref/identifier_schemes",
    "/requester_ref/profile",
    "/target_ref/type",
    "/target_ref/identifier_schemes",
    "/target_ref/profile",
    "/provenance/generated_by/policy_id",
    "/provenance/generated_by/policy_version",
    "/provenance/generated_by/policy_hash",
];

const LIVE_RESULT_SCHEMA_EXCLUDED_PATHS: &[&str] = &[
    "/provenance/generated_by/pack_id",
    "/provenance/generated_by/pack_version",
];

fn validate_live_result_raw_schema(
    result: &Value,
    result_object: &Map<String, Value>,
) -> Result<()> {
    if !result_object.contains_key("expires_at") {
        bail!(
            "governed Notary result does not match the closed public claim-result schema: expires_at is required"
        );
    }
    if LIVE_RESULT_OPTIONAL_NON_NULL_PATHS
        .iter()
        .any(|pointer| result.pointer(pointer).is_some_and(Value::is_null))
    {
        bail!("governed Notary result optional public field cannot be null");
    }
    if LIVE_RESULT_SCHEMA_EXCLUDED_PATHS
        .iter()
        .any(|pointer| result.pointer(pointer).is_some())
    {
        bail!("governed Notary result exceeds the closed public claim-result schema");
    }
    Ok(())
}

fn validate_live_result_reference_handles(
    result: &registry_notary_core::ClaimResultView,
) -> Result<()> {
    if !is_notary_pseudonymous_handle(&result.target_ref.handle)
        || result
            .requester_ref
            .as_ref()
            .is_some_and(|requester| !is_notary_pseudonymous_handle(&requester.handle))
    {
        bail!("governed Notary result contains an invalid pseudonymous reference handle");
    }
    Ok(())
}

fn is_notary_pseudonymous_handle(value: &str) -> bool {
    let digest = value
        .strip_prefix("rnref:v1:hmac-sha256:")
        .or_else(|| value.strip_prefix("rnref:v1:sha256:"));
    digest.is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn validate_live_result_redaction(
    result: &registry_notary_core::ClaimResultView,
    expected_redacted_fields: Option<&Value>,
    expected_disclosure: Option<&Value>,
) -> Result<()> {
    let disclosure = registry_notary_core::DisclosureProfile::parse(&result.disclosure)
        .ok_or_else(|| anyhow!("governed Notary result has an invalid disclosure profile"))?;
    match disclosure {
        registry_notary_core::DisclosureProfile::Redacted => {
            let expected_markers = match expected_redacted_fields {
                Some(fields) => validate_live_expected_redaction_fields(fields)?,
                None => vec![result.claim_id.clone()],
            };
            if result.value.is_some()
                || result.satisfied.is_some()
                || result.redacted_fields != expected_markers
                || expected_disclosure.and_then(Value::as_str) != Some("redacted")
            {
                bail!("governed Notary result violates full-redaction semantics");
            }
        }
        registry_notary_core::DisclosureProfile::Predicate => {
            if !result.redacted_fields.is_empty() || expected_redacted_fields.is_some() {
                bail!("governed Notary result exposes a predicate over redacted fields");
            }
            let predicate_value = result.value.as_ref().and_then(Value::as_bool);
            if predicate_value.is_none() || predicate_value != result.satisfied {
                bail!("governed Notary result has invalid predicate evidence semantics");
            }
        }
        registry_notary_core::DisclosureProfile::Value => {
            if expected_redacted_fields.is_some() {
                bail!("live expected redacted_fields apply only to a fully redacted claim result");
            }
            if result.satisfied != result.value.as_ref().and_then(Value::as_bool) {
                bail!("governed Notary result has invalid value evidence semantics");
            }
            if result.redacted_fields.is_empty() {
                return Ok(());
            }
            let Some(value) = result.value.as_ref().and_then(Value::as_object) else {
                bail!("governed Notary result has invalid field-redaction semantics");
            };
            let unique = result
                .redacted_fields
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if result.satisfied.is_some()
                || result.redacted_fields.len() > MAX_OUTPUTS
                || unique.len() != result.redacted_fields.len()
                || unique.iter().any(|field| {
                    !is_live_top_level_redaction_field(field) || value.contains_key(*field)
                })
            {
                bail!("governed Notary result has invalid field-redaction semantics");
            }
        }
    }
    Ok(())
}

fn validate_live_expected_redaction_fields(fields: &Value) -> Result<Vec<String>> {
    let fields = fields
        .as_array()
        .filter(|fields| !fields.is_empty() && fields.len() <= MAX_OUTPUTS)
        .ok_or_else(|| anyhow!("live expected redacted_fields have an invalid bounded shape"))?;
    let mut unique = BTreeSet::new();
    for field in fields {
        let field = field
            .as_str()
            .filter(|field| is_live_top_level_redaction_field(field))
            .ok_or_else(|| {
                anyhow!("live expected redacted_fields have an invalid bounded shape")
            })?;
        if !unique.insert(field.to_string()) {
            bail!("live expected redacted_fields have an invalid bounded shape");
        }
    }
    Ok(unique.into_iter().collect())
}

fn is_live_top_level_redaction_field(field: &str) -> bool {
    field != "value"
        && !field.contains('.')
        && validate_stable_id(field, "live expected redacted field").is_ok()
}

fn validate_live_notary_origin(value: &str) -> Result<url::Url> {
    if value.len() > 2048 || value.trim() != value {
        bail!("live Notary origin has an invalid bounded shape");
    }
    let origin = url::Url::parse(value).context("live Notary origin is not a URL")?;
    let loopback_http = origin.scheme() == "http"
        && match origin.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain(_)) | None => false,
        };
    if (origin.scheme() != "https" && !loopback_http)
        || origin.host().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        bail!("live Notary origin must be an HTTPS origin or an HTTP loopback origin");
    }
    Ok(origin)
}

fn read_bounded_external_request(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .context("failed to open the live request file safely")?;
        fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .context("failed to open the live request file")?;

    let metadata = file
        .metadata()
        .context("failed to inspect the opened live request file")?;
    if !metadata.is_file() || metadata.len() > MAX_AUTHORED_FILE_BYTES {
        bail!("live request must be a bounded regular file, not a symlink");
    }
    let mut bytes = Vec::new();
    file.take(MAX_AUTHORED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("failed to read the live request file")?;
    if bytes.len() as u64 > MAX_AUTHORED_FILE_BYTES {
        bail!("live request exceeds the authored file-size bound");
    }
    Ok(bytes)
}

#[cfg(test)]
mod external_request_reader_tests {
    use super::*;

    #[test]
    fn live_request_reader_rejects_oversize_after_opening() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("oversize.json");
        let file = fs::File::create(&path).expect("oversize file creates");
        file.set_len(MAX_AUTHORED_FILE_BYTES + 1)
            .expect("oversize file extends");

        let error = read_bounded_external_request(&path).expect_err("oversize must fail");
        assert!(format!("{error:#}").contains("bounded regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn live_request_reader_rejects_fifo_without_blocking() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("request.pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("mkfifo runs");
        assert!(status.success(), "mkfifo creates the test fixture");

        let error = read_bounded_external_request(&path).expect_err("FIFO must fail");
        assert!(format!("{error:#}").contains("bounded regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn live_request_reader_rejects_symlink_at_open() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("request.json");
        fs::write(&target, b"{}\n").expect("target writes");
        let link = directory.path().join("request-link.json");
        symlink(&target, &link).expect("symlink creates");

        let error = read_bounded_external_request(&link).expect_err("symlink must fail");
        assert!(format!("{error:#}").contains("open the live request file safely"));
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ValidatedLiveRequest {
    claims: Vec<String>,
    claim_versions: BTreeMap<String, String>,
    notary_service_id: String,
    subject_type: String,
}

struct PreparedGovernedLiveRequest {
    validated: ValidatedLiveRequest,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
struct GovernedLiveInputContract<'a> {
    name: &'a str,
    declaration: &'a InputDeclaration,
}

fn prepare_governed_live_request(
    loaded: &LoadedRegistryProject,
    request: &Value,
) -> Result<PreparedGovernedLiveRequest> {
    let (validated, outbound) = validate_live_request_boundary(loaded, request)?;
    let body = serde_json::to_vec(&outbound)
        .context("failed to construct the validated governed Notary request")?;
    Ok(PreparedGovernedLiveRequest { validated, body })
}

#[cfg(test)]
fn validate_live_request(
    loaded: &LoadedRegistryProject,
    request: &Value,
) -> Result<ValidatedLiveRequest> {
    validate_live_request_boundary(loaded, request).map(|(validated, _)| validated)
}

fn validate_live_request_boundary(
    loaded: &LoadedRegistryProject,
    request: &Value,
) -> Result<(ValidatedLiveRequest, GovernedLiveRequest)> {
    if !request.is_object() {
        bail!("live request must be a JSON object");
    }
    if contains_sensitive_request_key(request) {
        bail!("live request contains a forbidden credential-like field");
    }
    let outbound: GovernedLiveRequest = serde_json::from_value(request.clone())
        .map_err(|_| anyhow!("live request does not match the closed governed schema"))?;
    let validated = validate_governed_request(loaded, &outbound, true)?;
    Ok((validated, outbound))
}

fn validate_governed_request(
    loaded: &LoadedRegistryProject,
    outbound: &GovernedLiveRequest,
    require_notary_service: bool,
) -> Result<ValidatedLiveRequest> {
    let notary_service_id = loaded
        .environment
        .as_ref()
        .and_then(|environment| environment.deployment.notary.as_ref())
        .map(|notary| notary.service.clone())
        .map_or_else(
            || {
                if require_notary_service {
                    Err(anyhow!(
                        "live request environment does not declare a Notary service"
                    ))
                } else {
                    Ok("offline-fixture".to_owned())
                }
            },
            Ok,
        )?;
    let purpose = outbound.purpose.as_str();
    let services = loaded
        .project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::Evidence && service.purpose == purpose)
        .collect::<Vec<_>>();
    if services.is_empty() {
        bail!("live request purpose is not declared by this project");
    }
    let claims = &outbound.claims;
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        bail!("live request claim count is outside the project bound");
    }
    let mut ids = Vec::with_capacity(claims.len());
    let mut claim_versions = BTreeMap::new();
    let mut selected_claims = Vec::with_capacity(claims.len());
    for claim in claims {
        let id = claim.id.as_str();
        let service = services
            .iter()
            .copied()
            .find(|service| service.claims.contains_key(id))
            .ok_or_else(|| anyhow!("live request contains an unknown project claim"))?;
        let authored_version = service.version.to_string();
        if claim
            .version
            .as_deref()
            .is_some_and(|version| version != authored_version)
        {
            bail!("live request claim version does not match the authored project");
        }
        if claim_versions
            .insert(id.to_string(), authored_version)
            .is_some()
        {
            bail!("live request contains an unknown or duplicate project claim");
        }
        ids.push(id.to_string());
        let selected_claim = service
            .claims
            .get(id)
            .ok_or_else(|| anyhow!("selected project claim is absent after claim resolution"))?;
        selected_claims.push((service, selected_claim));
    }
    let first_claim = selected_claims
        .first()
        .map(|(_, claim)| *claim)
        .ok_or_else(|| anyhow!("live request must select at least one project claim"))?;
    let disclosure = outbound
        .disclosure
        .as_deref()
        .unwrap_or_else(|| expanded_disclosure(&first_claim.disclosure).0);
    if registry_notary_core::DisclosureProfile::parse(disclosure).is_none() {
        bail!("live request disclosure profile is invalid");
    }
    if selected_claims.iter().any(|(_, claim)| {
        !expanded_disclosure(&claim.disclosure)
            .1
            .contains(&disclosure)
    }) {
        bail!("live request disclosure is not allowed for every selected project claim");
    }
    if outbound
        .format
        .as_deref()
        .is_some_and(|format| format != registry_notary_core::FORMAT_CLAIM_RESULT_JSON)
    {
        bail!("live request format must be the governed claim-result media type");
    }
    for (name, _) in outbound.variables.iter() {
        if !selected_claims
            .iter()
            .any(|(service, _)| service.variables.contains_key(name))
        {
            bail!("live request variable is not declared by a selected project service");
        }
    }
    let subject_type = selected_claim_subject_type(&selected_claims)?;
    let mut input_claims = selected_claims.clone();
    let representative_binding = loaded
        .environment
        .as_ref()
        .and_then(|environment| environment.oid4vci.as_ref())
        .and_then(|binding| {
            binding
                .representative_issuance
                .as_ref()
                .map(|representative| (binding, representative))
        });
    if let Some((binding, representative)) = representative_binding {
        if let Some(proof_claim) = representative_proof_claim_for_selected_ids(
            &loaded.project,
            &binding.credential.service,
            &binding.credential.profile,
            &representative.proof_claim,
            &ids,
        )? {
            input_claims.push(proof_claim);
        }
    }
    validate_governed_live_target(
        loaded,
        &input_claims,
        outbound.requester.as_ref(),
        &outbound.target,
        &outbound.variables,
        subject_type,
    )?;
    Ok(ValidatedLiveRequest {
        claims: ids,
        claim_versions,
        notary_service_id,
        subject_type: subject_type.to_string(),
    })
}

fn representative_proof_claim_for_selected_ids<'a>(
    project: &'a RegistryProject,
    service_id: &str,
    profile_id: &str,
    proof_claim_id: &str,
    selected_claim_ids: &[String],
) -> Result<Option<(&'a ServiceDeclaration, &'a ClaimDeclaration)>> {
    let service = project
        .services
        .get(service_id)
        .ok_or_else(|| anyhow!("representative credential service is absent"))?;
    let credential = service
        .credential_profiles
        .get(profile_id)
        .ok_or_else(|| anyhow!("representative credential profile is absent"))?;
    let selected_root = credential
        .claims
        .first()
        .is_some_and(|root| selected_claim_ids.iter().any(|selected| selected == root));
    if !selected_root
        || selected_claim_ids
            .iter()
            .any(|selected| selected == proof_claim_id)
    {
        return Ok(None);
    }
    let proof_claim = service
        .claims
        .get(proof_claim_id)
        .ok_or_else(|| anyhow!("representative proof claim is absent"))?;
    Ok(Some((service, proof_claim)))
}

fn selected_claim_subject_type(
    selected_claims: &[(&ServiceDeclaration, &ClaimDeclaration)],
) -> Result<&'static str> {
    let mut subject_types = selected_claims
        .iter()
        .map(|(service, _)| service.effective_subject_type())
        .collect::<BTreeSet<_>>();
    if subject_types.len() != 1 {
        bail!("live request cannot combine evidence services with different subject types");
    }
    Ok(subject_types
        .pop_first()
        .ok_or_else(|| anyhow!("live request selected no evidence service"))?
        .as_str())
}

fn validate_governed_live_target(
    loaded: &LoadedRegistryProject,
    selected_claims: &[(&ServiceDeclaration, &ClaimDeclaration)],
    requester: Option<&GovernedLiveTarget>,
    target: &GovernedLiveTarget,
    variables: &registry_notary_core::RequestVariables,
    subject_type: &str,
) -> Result<()> {
    if !target.entity_type.eq_ignore_ascii_case(subject_type) {
        bail!("live request target type does not match the authored project");
    }

    let mut id_contracts = Vec::new();
    let mut identifier_contracts = BTreeMap::<String, Vec<GovernedLiveInputContract<'_>>>::new();
    let mut requester_identifier_contracts =
        BTreeMap::<String, Vec<GovernedLiveInputContract<'_>>>::new();
    let mut attribute_contracts = BTreeMap::<String, Vec<GovernedLiveInputContract<'_>>>::new();
    let mut variable_contracts = BTreeMap::<String, Vec<GovernedLiveInputContract<'_>>>::new();
    for (service, claim) in selected_claims {
        if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
            bail!("governed live requests require registry-backed project claims");
        }
        let consultation_name = claim_consultation_name(service, claim)?;
        let consultation = service
            .consultations
            .get(consultation_name)
            .ok_or_else(|| anyhow!("selected project claim has no authored live consultation"))?;
        let integration = loaded
            .integrations
            .get(&consultation.integration)
            .ok_or_else(|| anyhow!("selected live consultation has no authored integration"))?;
        for (name, mapping) in &consultation.input {
            let declaration = integration.document.input.get(name).ok_or_else(|| {
                anyhow!("selected live consultation input has no authored contract")
            })?;
            let contract = GovernedLiveInputContract { name, declaration };
            if mapping == "request.target.id" {
                id_contracts.push(contract);
            } else if let Some(scheme) = mapping.strip_prefix("request.target.identifiers.") {
                identifier_contracts
                    .entry(scheme.to_string())
                    .or_default()
                    .push(contract);
            } else if let Some(scheme) = mapping.strip_prefix("request.requester.identifiers.") {
                requester_identifier_contracts
                    .entry(scheme.to_string())
                    .or_default()
                    .push(contract);
            } else if let Some(name) = mapping.strip_prefix("request.target.attributes.") {
                attribute_contracts
                    .entry(name.to_string())
                    .or_default()
                    .push(contract);
            } else if let Some(name) = mapping.strip_prefix("request.variables.") {
                variable_contracts
                    .entry(name.to_string())
                    .or_default()
                    .push(contract);
            } else {
                bail!("authored consultation uses an unsupported governed live input");
            }
        }
    }

    if id_contracts.is_empty() != target.id.is_none() {
        bail!("live request target fields do not exactly match the selected authored inputs");
    }
    if requester_identifier_contracts.is_empty() != requester.is_none() {
        bail!(
            "live request requester must be present exactly when selected claims bind authenticated requester identifiers"
        );
    }
    let mut identifiers = BTreeMap::new();
    for identifier in &target.identifiers {
        if identifiers
            .insert(identifier.scheme.as_str(), identifier.value.as_str())
            .is_some()
        {
            bail!("live request target contains a duplicate identifier scheme");
        }
    }
    if identifiers.keys().copied().collect::<BTreeSet<_>>()
        != identifier_contracts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
        || target
            .attributes
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != attribute_contracts
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
    {
        bail!("live request target fields do not exactly match the selected authored inputs");
    }
    if let Some(requester) = requester {
        validate_governed_requester_type(requester)?;
        if requester.id.is_some() || !requester.attributes.is_empty() {
            bail!(
                "live request requester must contain only the required authenticated identifiers"
            );
        }
        let mut requester_identifiers = BTreeMap::new();
        for identifier in &requester.identifiers {
            if requester_identifiers
                .insert(identifier.scheme.as_str(), identifier.value.as_str())
                .is_some()
            {
                bail!("live request requester contains a duplicate identifier scheme");
            }
        }
        if requester_identifiers.keys().copied().collect::<BTreeSet<_>>()
            != requester_identifier_contracts
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        {
            bail!(
                "live request requester identifiers do not exactly match the selected authored inputs"
            );
        }
        for (scheme, contracts) in &requester_identifier_contracts {
            let value = requester_identifiers.get(scheme.as_str()).ok_or_else(|| {
                anyhow!(
                    "live request requester identifier is absent after exact-shape validation"
                )
            })?;
            validate_governed_live_input(
                &format!("requester.identifiers.{scheme}"),
                contracts,
                &Value::String((*value).to_string()),
            )?;
        }
    }

    if let Some(id) = &target.id {
        validate_governed_live_input("target.id", &id_contracts, &Value::String(id.clone()))?;
    }
    for (scheme, contracts) in &identifier_contracts {
        let value = identifiers.get(scheme.as_str()).ok_or_else(|| {
            anyhow!("live request target identifier is absent after exact-shape validation")
        })?;
        validate_governed_live_input(
            &format!("target.identifiers.{scheme}"),
            contracts,
            &Value::String((*value).to_string()),
        )?;
    }
    for (name, contracts) in &attribute_contracts {
        let value = target.attributes.get(name).ok_or_else(|| {
            anyhow!("live request target attribute is absent after exact-shape validation")
        })?;
        validate_governed_live_input(&format!("target.attributes.{name}"), contracts, value)?;
    }
    for (name, contracts) in &variable_contracts {
        let value = variables.get(name).ok_or_else(|| {
            anyhow!("live request omits a variable required by the selected authored inputs")
        })?;
        validate_governed_live_input(
            &format!("variables.{name}"),
            contracts,
            &Value::String(value.to_string()),
        )?;
    }
    Ok(())
}

fn validate_governed_requester_type(requester: &GovernedLiveTarget) -> Result<()> {
    if !requester.entity_type.eq_ignore_ascii_case("person") {
        bail!("live request requester type must be Person");
    }
    Ok(())
}

fn validate_governed_live_input(
    path: &str,
    contracts: &[GovernedLiveInputContract<'_>],
    value: &Value,
) -> Result<()> {
    for contract in contracts {
        validate_fixture_input_value(contract.name, contract.declaration, value).map_err(|_| {
            anyhow!("live request {path} violates its selected authored type or bounds")
        })?;
    }
    Ok(())
}

fn contains_sensitive_request_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "credential" | "credentials" | "password" | "secret" | "token" | "api_key"
            ) || contains_sensitive_request_key(value)
        }),
        Value::Array(values) => values.iter().any(contains_sensitive_request_key),
        _ => false,
    }
}

#[cfg(test)]
mod governed_live_request_boundary_tests {
    use super::*;

    fn loaded_project(name: &str) -> LoadedRegistryProject {
        load_registry_project(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring")
                .join(name),
            Some("local"),
        )
        .unwrap_or_else(|error| panic!("{name} project loads: {error:#}"))
    }

    fn openspp_request() -> Value {
        json!({
            "target": {
                "type": "Person",
                "identifiers": [{
                    "scheme": "openspp_individual_id",
                    "value": "IND-AB12CD34",
                }],
            },
            "claims": ["social-registry-record-exists"],
            "disclosure": "predicate",
            "format": registry_notary_core::FORMAT_CLAIM_RESULT_JSON,
            "purpose": "social-programme-verification",
        })
    }

    #[test]
    fn representative_root_adds_its_derived_proof_to_input_validation() {
        let loaded = loaded_project("custom-system");
        let selected = vec!["household-record-exists".to_string()];
        let (service, proof) = representative_proof_claim_for_selected_ids(
            &loaded.project,
            "household-eligibility",
            "household-eligibility",
            "source-household-approval-decision",
            &selected,
        )
        .expect("representative proof selection validates")
        .expect("selected representative root adds its proof");
        assert_eq!(
            claim_consultation_name(service, proof).expect("proof consultation resolves"),
            "household"
        );
        assert!(
            representative_proof_claim_for_selected_ids(
                &loaded.project,
                "household-eligibility",
                "household-eligibility",
                "source-household-approval-decision",
                &[
                    "household-record-exists".to_string(),
                    "source-household-approval-decision".to_string(),
                ],
            )
            .expect("explicit proof selection validates")
            .is_none(),
            "an explicitly selected proof is not added twice"
        );
    }

    #[test]
    fn representative_requester_type_matches_the_production_ceremony() {
        let requester = GovernedLiveTarget {
            entity_type: "Organisation".to_string(),
            id: None,
            identifiers: Vec::new(),
            attributes: BTreeMap::new(),
        };

        let error = validate_governed_requester_type(&requester)
            .expect_err("non-person requester must be rejected");
        assert_eq!(
            error.to_string(),
            "live request requester type must be Person"
        );
    }

    fn assert_rejected_before_outbound_body(
        loaded: &LoadedRegistryProject,
        request: &Value,
        expected_error: &str,
    ) -> String {
        let error = prepare_governed_live_request(loaded, request)
            .err()
            .expect("invalid input must not produce an outbound request body");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected_error),
            "unexpected error: {rendered}"
        );
        rendered
    }

    #[test]
    fn governed_live_request_rejects_unknown_top_level_before_outbound_body() {
        let loaded = loaded_project("openspp-exact");
        let mut request = openspp_request();
        request["raw_record"] = json!({ "national_id": "NID-raw-top-level" });

        let error =
            assert_rejected_before_outbound_body(&loaded, &request, "closed governed schema");
        for private_fragment in ["raw_record", "national_id", "NID-raw-top-level"] {
            assert!(
                !error.contains(private_fragment),
                "closed-schema errors must redact unknown names and values"
            );
        }
    }

    #[test]
    fn governed_live_request_rejects_unknown_nested_field_before_outbound_body() {
        let loaded = loaded_project("openspp-exact");
        let mut request = openspp_request();
        request["target"]["raw_record"] = json!({ "record": "unreviewed" });

        let error =
            assert_rejected_before_outbound_body(&loaded, &request, "closed governed schema");
        for private_fragment in ["raw_record", "record", "unreviewed"] {
            assert!(
                !error.contains(private_fragment),
                "closed-schema errors must redact unknown names and values"
            );
        }
    }

    #[test]
    fn governed_live_request_rejects_unmapped_pii_shaped_field_before_outbound_body() {
        let loaded = loaded_project("openspp-exact");
        let mut request = openspp_request();
        request["target"]["attributes"]["national_id"] = json!("NID-private-value");

        let error = assert_rejected_before_outbound_body(
            &loaded,
            &request,
            "do not exactly match the selected authored inputs",
        );
        for private_fragment in ["national_id", "NID-private-value"] {
            assert!(
                !error.contains(private_fragment),
                "live validation errors must redact unknown names and values"
            );
        }
    }

    #[test]
    fn governed_live_request_validates_identifier_and_attribute_bounds() {
        let openspp = loaded_project("openspp-exact");
        let mut oversized_identifier = openspp_request();
        oversized_identifier["target"]["identifiers"][0]["value"] = json!("X".repeat(257));
        assert_rejected_before_outbound_body(
            &openspp,
            &oversized_identifier,
            "violates its selected authored type or bounds",
        );

        let dhis2 = loaded_project("dhis2-script");
        let invalid_attribute = json!({
            "target": {
                "type": "person",
                "identifiers": [{
                    "scheme": "dhis2_tracked_entity",
                    "value": "A1234567890",
                }],
                "attributes": { "include_inactive": "false" },
            },
            "variables": { "as_of_date": "2026-01-01" },
            "claims": ["child-age-band"],
            "disclosure": "value",
            "purpose": "programme-enrollment-verification",
        });
        assert_rejected_before_outbound_body(
            &dhis2,
            &invalid_attribute,
            "violates its selected authored type or bounds",
        );
    }

    #[test]
    fn governed_live_request_reconstructs_declared_typed_target_and_variables() {
        let loaded = loaded_project("dhis2-script");
        let request = json!({
            "target": {
                "type": "Person",
                "identifiers": [{
                    "scheme": "dhis2_tracked_entity",
                    "value": "A1234567890",
                }],
                "attributes": { "include_inactive": false },
            },
            "variables": { "as_of_date": "2026-01-01" },
            "claims": ["child-age-band"],
            "disclosure": "value",
            "format": registry_notary_core::FORMAT_CLAIM_RESULT_JSON,
            "purpose": "programme-enrollment-verification",
        });

        let prepared = prepare_governed_live_request(&loaded, &request)
            .expect("declared typed live request prepares");
        let outbound =
            parse_json_strict(&prepared.body).expect("prepared outbound body is strict JSON");
        assert_eq!(
            outbound.pointer("/target/identifiers/0/value"),
            Some(&json!("A1234567890"))
        );
        assert_eq!(
            outbound.pointer("/target/attributes/include_inactive"),
            Some(&json!(false))
        );
        assert_eq!(
            outbound.pointer("/variables/as_of_date"),
            Some(&json!("2026-01-01"))
        );
        assert!(outbound.get("raw_record").is_none());
    }

    #[test]
    fn governed_live_request_rejects_undeclared_variables_and_formats() {
        let loaded = loaded_project("openspp-exact");
        let mut variable = openspp_request();
        variable["variables"] = json!({ "as_of_date": "2026-01-01" });
        assert_rejected_before_outbound_body(
            &loaded,
            &variable,
            "variable is not declared by a selected project service",
        );

        let mut format = openspp_request();
        format["format"] = json!("application/json");
        assert_rejected_before_outbound_body(&loaded, &format, "governed claim-result media type");
    }
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
    let (fixtures, generated_observations, request_observations, call_budget_actual) =
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
        &request_observations,
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
    let (requires_relay, requires_notary) = project_product_topology(&loaded.project);
    if requires_relay {
        input.require_product(PreflightProduct::RegistryRelay);
        input.record_product_validator_available(PreflightProduct::RegistryRelay);
    }
    if requires_notary {
        input.require_product(PreflightProduct::RegistryNotary);
        input.record_product_validator_available(PreflightProduct::RegistryNotary);
    }
    Ok(run_offline_preflight(input))
}

/// Compare the normalized, environment-bound project state with a verified
/// reviewed baseline. This command deliberately never exposes digest values,
/// authored values, environment names, or filesystem paths in its report.
pub fn promote_registry_project(
    options: &ProjectPromotionOptions,
) -> Result<ProjectPromotionReportV1> {
    validate_promotion_baseline_options(options)?;

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
    .map_err(|_| anyhow!("could not load promotion state safely"))?;
    preflight_project_rhai_scripts(&loaded)
        .map_err(|_| anyhow!("promotion state could not be validated safely"))?;

    // The compiler and product validators establish that the state being
    // compared is a valid offline product input. Their detailed errors can
    // carry local identifiers or paths, so promotion deliberately returns a
    // value-free boundary error instead.
    let compiled = compile_project(&loaded, None)
        .map_err(|_| anyhow!("promotion state could not be compiled safely"))?;
    validate_generated_product_configs(&compiled)
        .map_err(|_| anyhow!("promotion compatibility could not be established safely"))?;

    let baselines = match load_verified_promotion_baselines(options, &loaded) {
        Ok(baselines) => baselines,
        Err(_) if promotion_baseline_supplied(options) => {
            return unresolved_promotion_baseline_report();
        }
        Err(_) => return Err(anyhow!("could not establish verified promotion baselines")),
    };

    let baseline_values = baselines.iter().cloned().collect::<Vec<_>>();
    build_promotion_report_from_normalized_state(
        &loaded,
        &compiled.approval_state,
        &baseline_values,
    )
    .map_err(|_| anyhow!("promotion comparison could not be classified safely"))
}

fn validate_promotion_baseline_options(options: &ProjectPromotionOptions) -> Result<()> {
    validate_approved_baseline_set_paths(ApprovedBaselineSetPaths::promotion(options))
}

fn promotion_baseline_supplied(options: &ProjectPromotionOptions) -> bool {
    options.against.is_some() || options.relay_against.is_some() || options.notary_against.is_some()
}

fn unresolved_promotion_baseline_report() -> Result<ProjectPromotionReportV1> {
    build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision: ReviewedRevisionComparison::NotProven,
        changes: Vec::new(),
        reviewed_ceiling: ReviewedCeilingInput::Unresolved,
        trust: TrustResolutionInput::Unresolved,
        compatibility: PromotionCompatibilityInput {
            product: PromotionCompatibilityState::Unresolved,
            capability: PromotionCompatibilityState::Unresolved,
            schema: PromotionCompatibilityState::Unresolved,
            abi: PromotionCompatibilityState::Unresolved,
        },
    })
    .map_err(|_| anyhow!("promotion comparison exceeded its bounded change capacity"))
}

fn validate_named_baseline_pair(
    against_name: &str,
    against: Option<&Path>,
    anchor_name: &str,
    anchor: Option<&Path>,
) -> Result<()> {
    if against.is_some() != anchor.is_some() {
        bail!("{against_name} and {anchor_name} must be supplied together");
    }
    Ok(())
}

fn load_verified_promotion_baselines(
    options: &ProjectPromotionOptions,
    loaded: &LoadedRegistryProject,
) -> Result<VerifiedBaselineSet> {
    load_verified_approved_baseline_set(
        ApprovedBaselineSetPaths::promotion(options),
        loaded,
        BaselineSetCompleteness::CompleteTopologyWhenPresent,
    )
}

fn build_promotion_report_from_normalized_state(
    loaded: &LoadedRegistryProject,
    current_approval_state: &Value,
    baselines: &[VerifiedBaseline],
) -> Result<ProjectPromotionReportV1> {
    let current = promotion_projection_from_approval_state(current_approval_state, true)?;
    let current_compatibility =
        promotion_compatibility(loaded, current_approval_state, &current, baselines)?;

    let Some(baseline) = baselines.first() else {
        return build_project_promotion_report(ProjectPromotionInput {
            reviewed_revision: ReviewedRevisionComparison::NotProven,
            changes: Vec::new(),
            reviewed_ceiling: ReviewedCeilingInput::WithinReviewedCeiling,
            trust: TrustResolutionInput::Unresolved,
            compatibility: current_compatibility,
        })
        .map_err(|_| anyhow!("promotion comparison exceeded its bounded change capacity"));
    };

    if baselines.iter().any(|baseline| {
        baseline
            .approval_state
            .get("promotion_projection")
            .is_none()
    }) {
        return build_project_promotion_report(ProjectPromotionInput {
            reviewed_revision: ReviewedRevisionComparison::NotProven,
            changes: Vec::new(),
            reviewed_ceiling: ReviewedCeilingInput::Unresolved,
            trust: TrustResolutionInput::Unresolved,
            compatibility: current_compatibility,
        })
        .map_err(|_| anyhow!("promotion comparison exceeded its bounded change capacity"));
    }

    let previous = promotion_projection_from_approval_state(&baseline.approval_state, false)?;
    if baselines.iter().skip(1).any(|baseline| {
        match promotion_projection_from_approval_state(&baseline.approval_state, false) {
            Ok(projection) => projection != previous,
            Err(_) => true,
        }
    }) {
        return build_project_promotion_report(ProjectPromotionInput {
            reviewed_revision: ReviewedRevisionComparison::NotProven,
            changes: Vec::new(),
            reviewed_ceiling: ReviewedCeilingInput::Unresolved,
            trust: TrustResolutionInput::Unresolved,
            compatibility: PromotionCompatibilityInput {
                schema: PromotionCompatibilityState::Incompatible,
                ..current_compatibility
            },
        })
        .map_err(|_| anyhow!("promotion comparison exceeded its bounded change capacity"));
    }
    let current_fields = current.fields_by_kind();
    let previous_fields = previous.fields_by_kind();
    let mut changes = Vec::new();
    let mut reviewed_ceiling = ReviewedCeilingInput::WithinReviewedCeiling;
    let mut trust = TrustResolutionInput::Resolved;

    for kind in PromotionChangeKind::ALL {
        let current = current_fields
            .get(&kind)
            .ok_or_else(|| anyhow!("current promotion projection is incomplete"))?;
        let previous = previous_fields
            .get(&kind)
            .ok_or_else(|| anyhow!("baseline promotion projection is incomplete"))?;
        if current.digest == previous.digest {
            continue;
        }
        let effect = classify_projected_change_effect(kind, previous, current);
        if kind == PromotionChangeKind::IntegrationCeiling {
            reviewed_ceiling = match effect {
                PromotionChangeEffect::Narrowed => ReviewedCeilingInput::Narrowed,
                PromotionChangeEffect::Widened => ReviewedCeilingInput::Widened,
                PromotionChangeEffect::ChangedWithinReviewedAuthority => {
                    ReviewedCeilingInput::WithinReviewedCeiling
                }
                PromotionChangeEffect::Unresolved => ReviewedCeilingInput::Unresolved,
            };
        }
        if kind == PromotionChangeKind::Trust && effect == PromotionChangeEffect::Unresolved {
            trust = TrustResolutionInput::Unresolved;
        }
        changes.push(PromotionChangeInput {
            kind,
            classification: Some(current.classification),
            ownership: current.ownership,
            effect,
        });
    }

    // Raw authored-input digests remain outside comparison evidence, so
    // formatting-only edits do not become a reviewed semantic revision.
    let reviewed_revision = if changes
        .iter()
        .any(|change| change.ownership == PromotionFieldOwnership::ReviewedProjectOwned)
    {
        ReviewedRevisionComparison::DifferentReviewedSemanticRevision
    } else {
        ReviewedRevisionComparison::SameReviewedSemanticRevision
    };

    build_project_promotion_report(ProjectPromotionInput {
        reviewed_revision,
        changes,
        reviewed_ceiling,
        trust,
        compatibility: current_compatibility,
    })
    .map_err(|_| anyhow!("promotion comparison exceeded its bounded change capacity"))
}

fn promotion_compatibility(
    loaded: &LoadedRegistryProject,
    current_approval_state: &Value,
    current: &ProjectPromotionProjectionV1,
    baselines: &[VerifiedBaseline],
) -> Result<PromotionCompatibilityInput> {
    let closures = current_approval_state
        .get("generated_closure_digests")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("current approval state lacks generated product closures"))?;
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("promotion compatibility requires an environment"))?;
    let declared_schemas = project_promotion_authoring_schemas(loaded, environment);
    let declared_products = project_promotion_products(environment);
    let product = if current.products.is_empty() || current.products != declared_products {
        PromotionCompatibilityState::Missing
    } else if [
        (PromotionProjectedProduct::Relay, "relay"),
        (PromotionProjectedProduct::Notary, "notary"),
    ]
    .into_iter()
    .all(|(product, name)| {
        let required = current.products.contains(&product);
        closures
            .get(name)
            .is_some_and(|digest| digest.is_string() == required && (required || digest.is_null()))
    }) {
        let baseline_products = baselines
            .iter()
            .map(verified_baseline_product)
            .collect::<Result<BTreeSet<_>>>()?;
        let current_products = current.products.iter().copied().collect::<BTreeSet<_>>();
        if baselines.is_empty() || baseline_products == current_products {
            PromotionCompatibilityState::Compatible
        } else if baseline_products.is_subset(&current_products) {
            PromotionCompatibilityState::Missing
        } else {
            PromotionCompatibilityState::Incompatible
        }
    } else {
        PromotionCompatibilityState::Missing
    };
    let declared_capabilities = project_promotion_capabilities(loaded, environment);
    let released_capabilities = loaded
        .integrations
        .values()
        .all(|integration| match &integration.document.capability {
            CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Snapshot { .. } => true,
            CapabilityDeclaration::Script { script } => {
                RELEASED_SCRIPT_RUNTIMES.contains(&match script.runtime {
                    ScriptRuntime::RhaiV1 => ReleasedScriptRuntime::RhaiV1,
                })
            }
        });
    let capability = if current.capabilities != declared_capabilities {
        PromotionCompatibilityState::Missing
    } else if released_capabilities {
        PromotionCompatibilityState::Compatible
    } else {
        PromotionCompatibilityState::Incompatible
    };
    let schema = if !baselines.is_empty() {
        if baselines.iter().any(|baseline| {
            baseline
                .approval_state
                .get("promotion_projection")
                .is_none()
        }) {
            PromotionCompatibilityState::Missing
        } else {
            let projections = baselines
                .iter()
                .map(|baseline| {
                    promotion_projection_from_approval_state(&baseline.approval_state, false)
                })
                .collect::<Result<Vec<_>>>()?;
            if current.authoring_schemas == declared_schemas
                && projections.iter().all(|previous| {
                    previous.authoring_schemas == current.authoring_schemas
                        && previous.field_knowledge_revision == current.field_knowledge_revision
                })
            {
                PromotionCompatibilityState::Compatible
            } else {
                PromotionCompatibilityState::Incompatible
            }
        }
    } else if current.authoring_schemas == declared_schemas {
        PromotionCompatibilityState::Compatible
    } else {
        PromotionCompatibilityState::Incompatible
    };
    let abi = if baselines.is_empty() {
        PromotionCompatibilityState::Unresolved
    } else if baselines.iter().all(|baseline| {
        baseline
            .approval_state
            .get("compiler_version")
            .and_then(Value::as_str)
            == Some(env!("CARGO_PKG_VERSION"))
    }) {
        PromotionCompatibilityState::Compatible
    } else {
        PromotionCompatibilityState::Incompatible
    };
    Ok(PromotionCompatibilityInput {
        product,
        capability,
        schema,
        abi,
    })
}

fn verified_baseline_product(baseline: &VerifiedBaseline) -> Result<PromotionProjectedProduct> {
    match baseline
        .verified_manifest
        .get("product")
        .and_then(Value::as_str)
    {
        Some("registry-relay") => Ok(PromotionProjectedProduct::Relay),
        Some("registry-notary") => Ok(PromotionProjectedProduct::Notary),
        _ => Err(anyhow!(
            "verified promotion baseline has an unsupported product"
        )),
    }
}

fn promotion_projection_from_approval_state(
    approval_state: &Value,
    require_current_field_knowledge: bool,
) -> Result<ProjectPromotionProjectionV1> {
    let projection: ProjectPromotionProjectionV1 = serde_json::from_value(
        approval_state
            .get("promotion_projection")
            .cloned()
            .ok_or_else(|| anyhow!("approval state lacks promotion projection"))?,
    )
    .context("approval promotion projection is invalid")?;
    if require_current_field_knowledge {
        validate_project_promotion_projection(&projection, PROMOTION_FIELD_KNOWLEDGE_REVISION)
            .map_err(|error| anyhow!(error))?;
    } else {
        validate_project_promotion_projection_structure(&projection)
            .map_err(|error| anyhow!(error))?;
    }
    Ok(projection)
}

#[cfg(test)]
mod promotion_adapter_tests {
    use super::*;

    fn current_approval_state(loaded: &LoadedRegistryProject) -> Value {
        let projection = project_promotion_projection(
            loaded,
            loaded
                .environment
                .as_ref()
                .expect("promotion fixture has an environment"),
        )
        .expect("projection builds");
        let relay = projection
            .products
            .contains(&PromotionProjectedProduct::Relay)
            .then_some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let notary = projection
            .products
            .contains(&PromotionProjectedProduct::Notary)
            .then_some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        json!({
            "schema": APPROVAL_STATE_SCHEMA,
            "authored_input_digest": loaded.authored_hash,
            "compiler_version": env!("CARGO_PKG_VERSION"),
            "generated_closure_digests": {
                "relay": relay,
                "notary": notary,
            },
            "promotion_projection": projection,
        })
    }

    fn verified_baselines(approval_state: Value) -> Vec<VerifiedBaseline> {
        vec![
            VerifiedBaseline {
                approval_state: approval_state.clone(),
                approval_state_digest:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                verified_manifest: json!({ "product": "registry-relay" }),
                review_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
            },
            VerifiedBaseline {
                approval_state,
                approval_state_digest:
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_string(),
                verified_manifest: json!({ "product": "registry-notary" }),
                review_digest:
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_string(),
            },
        ]
    }

    #[test]
    fn normalized_promotion_comparison_supports_safe_changes_and_blocks_unresolved_ceiling() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http");
        let loaded = load_registry_project(&root, Some("local")).expect("starter loads");
        let current = current_approval_state(&loaded);
        let serialized_projection =
            serde_json::to_string(&current["promotion_projection"]).expect("projection serializes");
        for forbidden in [
            "fictional-citizen-registry",
            "citizen-registry.invalid",
            "FICTIONAL_REGISTRY_TOKEN",
            "EVIDENCE_CLIENT_TOKEN_HASH",
            "public-service-person-verification",
            "person-verification",
            "person-record",
            "evidence-client",
            "fictional-registry-relay",
            "fictional-registry-notary",
            "project-issuer-key",
            root.to_str().expect("starter path is UTF-8"),
        ] {
            assert!(!serialized_projection.contains(forbidden));
        }
        let projection = promotion_projection_from_approval_state(&current, true)
            .expect("current projection validates");
        let projected_kinds = projection
            .fields
            .iter()
            .map(|field| field.kind)
            .collect::<BTreeSet<_>>();
        for kind in [
            PromotionChangeKind::Caller,
            PromotionChangeKind::Purpose,
            PromotionChangeKind::Origin,
            PromotionChangeKind::CredentialBinding,
            PromotionChangeKind::Operational,
            PromotionChangeKind::ProductEnablement,
            PromotionChangeKind::CapabilityEnablement,
        ] {
            assert!(projected_kinds.contains(&kind), "{kind:?}");
        }
        let mut reviewed_state = current.clone();
        reviewed_state["authored_input_digest"] = Value::String("different-raw-input".to_owned());
        let baselines = verified_baselines(reviewed_state);
        let ready = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("matching state compares");
        assert_eq!(ready.disposition, PromotionDisposition::Ready);

        let mut previous = current.clone();
        let origin_index = PromotionChangeKind::ALL
            .iter()
            .position(|kind| *kind == PromotionChangeKind::Origin)
            .expect("origin index");
        previous["promotion_projection"]["fields"][origin_index]["digest"] = Value::String(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned(),
        );
        let baselines = verified_baselines(previous);
        let changed = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("changed state compares");
        assert_eq!(
            changed.disposition,
            PromotionDisposition::ReadyAfterRequiredActions
        );
        assert_eq!(changed.changes[0].kind, PromotionChangeKind::Origin);
        assert_eq!(
            changed.changes[0].effect,
            PromotionChangeEffect::ChangedWithinReviewedAuthority
        );

        let changed_kinds = [
            PromotionChangeKind::Caller,
            PromotionChangeKind::Purpose,
            PromotionChangeKind::Origin,
            PromotionChangeKind::CredentialBinding,
            PromotionChangeKind::Operational,
            PromotionChangeKind::ProductEnablement,
            PromotionChangeKind::CapabilityEnablement,
        ];
        let mut previous = current.clone();
        for (offset, kind) in changed_kinds.iter().enumerate() {
            let index = PromotionChangeKind::ALL
                .iter()
                .position(|candidate| candidate == kind)
                .expect("projected kind index");
            let byte = b'1' + u8::try_from(offset).expect("bounded change offset");
            previous["promotion_projection"]["fields"][index]["digest"] = Value::String(format!(
                "sha256:{}",
                char::from(byte).to_string().repeat(64)
            ));
        }
        let baselines = verified_baselines(previous);
        let changed = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("all classified categories compare");
        assert_eq!(
            changed.disposition,
            PromotionDisposition::ReadyAfterRequiredActions
        );
        assert_eq!(
            changed
                .changes
                .iter()
                .map(|change| change.kind)
                .collect::<BTreeSet<_>>(),
            changed_kinds.into_iter().collect()
        );
        assert!(changed.changes.iter().all(|change| {
            change.effect == PromotionChangeEffect::ChangedWithinReviewedAuthority
        }));

        let mut previous = current.clone();
        let ceiling_index = PromotionChangeKind::ALL
            .iter()
            .position(|kind| *kind == PromotionChangeKind::IntegrationCeiling)
            .expect("ceiling index");
        previous["promotion_projection"]["fields"][ceiling_index]["digest"] = Value::String(
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
        );
        let baselines = verified_baselines(previous);
        let blocked = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("unresolved ceiling compares");
        assert_eq!(blocked.disposition, PromotionDisposition::Blocked);
        assert!(blocked
            .blocking_reasons
            .contains(&PromotionBlockingReason::UnresolvedChange));
        assert!(blocked
            .blocking_reasons
            .contains(&PromotionBlockingReason::ReviewedCeilingUnresolved));
        let serialized = serde_json::to_string(&changed).expect("changed report serializes");
        assert!(!serialized.contains("citizen-registry.invalid"));
        assert!(!serialized.contains(root.to_str().expect("starter path is UTF-8")));
    }

    #[test]
    fn new_or_changed_published_field_paths_require_promotion_mapping_review() {
        let revision = validate_promotion_field_knowledge_mapping()
            .expect("field knowledge mapping is current");
        assert_eq!(revision, PROMOTION_FIELD_KNOWLEDGE_REVISION);

        let index = knowledge::published_field_knowledge_index().expect("knowledge indexes");
        // Both the exact path count and the full knowledge-record digest are
        // intentional review pins. Adding or changing a published path without
        // updating its closed mapping and reviewed revision fails this test and
        // `project_promotion_projection`.
        assert_eq!(index.by_path().len(), 683);
        let mapped = index
            .by_path()
            .keys()
            .filter_map(promotion_kind_for_field_path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            mapped,
            PromotionChangeKind::ALL
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(index.by_path().keys().all(|path| {
            promotion_kind_for_field_path(path).is_some()
                || path.schema == knowledge::SchemaKind::Fixture
        }));
    }

    #[test]
    fn snapshot_environment_entity_enablement_is_bound_into_the_signed_capability_projection() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/snapshot-exact");
        let loaded = load_registry_project(&root, Some("local")).expect("snapshot project loads");
        let environment = loaded
            .environment
            .as_ref()
            .expect("snapshot project has an environment");
        let projection =
            project_promotion_projection(&loaded, environment).expect("projection builds");

        assert_eq!(
            projection.capabilities,
            vec![PromotionProjectedCapability::Snapshot]
        );
        let capability = projection
            .fields_by_kind()
            .get(&PromotionChangeKind::CapabilityEnablement)
            .copied()
            .expect("capability field is projected");
        assert_eq!(capability.authority_members.len(), 1);
        let integration = loaded
            .integrations
            .get("person-snapshot")
            .expect("snapshot integration exists");
        assert!(project_promotion_capability_enabled(
            "person-snapshot",
            &integration.document.capability,
            environment,
        ));
    }

    #[test]
    fn promotion_compatibility_is_derived_from_closures_schemas_and_compiler() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http");
        let loaded = load_registry_project(&root, Some("local")).expect("starter loads");
        let current = current_approval_state(&loaded);

        let mut missing_product = current.clone();
        missing_product["generated_closure_digests"]["notary"] = Value::Null;
        let report = build_promotion_report_from_normalized_state(&loaded, &missing_product, &[])
            .expect("missing product compatibility reports");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::MissingProduct));

        let mut previous = current.clone();
        previous["promotion_projection"]["authoring_schemas"]["environment"] = json!(2);
        let baselines = verified_baselines(previous);
        let report = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("schema mismatch reports");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::IncompatibleSchema));

        let mut previous = current.clone();
        previous["compiler_version"] = json!("0.0.0");
        let baselines = verified_baselines(previous);
        let report = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("compiler mismatch reports");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::IncompatibleAbi));

        let mut legacy = current.clone();
        legacy["schema"] = json!(APPROVAL_STATE_SCHEMA_V1);
        legacy
            .as_object_mut()
            .expect("legacy state is an object")
            .remove("promotion_projection");
        let baselines = verified_baselines(legacy);
        let report = build_promotion_report_from_normalized_state(&loaded, &current, &baselines)
            .expect("legacy signed baseline fails closed as a report");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::MissingSchema));
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::ReviewedRevisionNotProven));

        let baselines = verified_baselines(current.clone());
        let report =
            build_promotion_report_from_normalized_state(&loaded, &current, &baselines[1..])
                .expect("one product baseline reports missing combined closure");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::MissingProduct));

        let mut conflicting = verified_baselines(current.clone());
        let origin_index = PromotionChangeKind::ALL
            .iter()
            .position(|kind| *kind == PromotionChangeKind::Origin)
            .expect("origin index");
        conflicting[1].approval_state["promotion_projection"]["fields"][origin_index]["digest"] =
            json!("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let report = build_promotion_report_from_normalized_state(&loaded, &current, &conflicting)
            .expect("conflicting signed product projections fail closed");
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::IncompatibleSchema));
        assert!(report
            .blocking_reasons
            .contains(&PromotionBlockingReason::ReviewedRevisionNotProven));
    }

    #[test]
    fn promotion_baseline_options_require_complete_non_conflicting_pairs() {
        let root = PathBuf::from("/promotion-project");
        let bundle = PathBuf::from("/baseline");
        let anchor = PathBuf::from("/anchor");
        let mut options = ProjectPromotionOptions {
            project_directory: root,
            environment: "local".to_owned(),
            against: None,
            anchor: None,
            relay_against: Some(bundle.clone()),
            relay_anchor: None,
            notary_against: None,
            notary_anchor: None,
        };
        assert!(validate_promotion_baseline_options(&options).is_err());

        options.relay_anchor = Some(anchor.clone());
        options.against = Some(bundle);
        options.anchor = Some(anchor);
        assert!(validate_promotion_baseline_options(&options).is_err());
    }
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
            SupportComponent::RegistryNotaryProduct,
            SupportState::Available,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryRelayValidator,
            SupportState::Available,
            SupportEvidence::LinkedProductValidator,
        ),
        (
            SupportComponent::RegistryNotaryValidator,
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
            SupportComponent::RegistryNotaryConfigSchema,
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
        (
            SupportComponent::RegistryNotaryImage,
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
    let (requires_relay, requires_notary) = project_product_topology(&loaded.project);
    if requires_relay {
        declarations.insert(CapabilityId::RegistryRelayProduct);
    }
    if requires_notary {
        declarations.insert(CapabilityId::RegistryNotaryProduct);
    }
    if environment.deployment.relay.is_some() {
        enabled.insert(CapabilityId::RegistryRelayProduct);
    }
    if environment.deployment.notary.is_some() {
        enabled.insert(CapabilityId::RegistryNotaryProduct);
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
        for claim in service.claims.values() {
            if inferred_claim_evidence(service, claim)? != ClaimEvidence::RegistryBacked {
                continue;
            }
            let consultation_name = claim_consultation_name(service, claim)?;
            let consultation = service
                .consultations
                .get(consultation_name)
                .ok_or_else(|| anyhow!("registry-backed claim consultation is unavailable"))?;
            let capability = *integration_capabilities
                .get(consultation.integration.as_str())
                .ok_or_else(|| anyhow!("consultation capability is unavailable"))?;
            let counts = usage.entry(capability).or_default();
            counts.claims = counts
                .claims
                .checked_add(1)
                .ok_or_else(|| anyhow!("capability claim count exceeds the report cap"))?;
        }
        let product = match service.kind {
            ServiceKind::RecordsApi => CapabilityId::RegistryRelayProduct,
            ServiceKind::Evidence => CapabilityId::RegistryNotaryProduct,
        };
        let counts = usage.entry(product).or_default();
        counts.services = counts
            .services
            .checked_add(1)
            .ok_or_else(|| anyhow!("product service count exceeds the report cap"))?;
        counts.consultations = counts
            .consultations
            .checked_add(u32::try_from(service.consultations.len())?)
            .ok_or_else(|| anyhow!("product consultation count exceeds the report cap"))?;
        counts.claims = counts
            .claims
            .checked_add(u32::try_from(service.claims.len())?)
            .ok_or_else(|| anyhow!("product claim count exceeds the report cap"))?;
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
    if let Some(issuance) = &environment.issuance {
        add_preflight_secret(
            &mut input,
            &environment_file,
            "/issuance/signing_key/secret",
            &issuance.signing_key,
            PreflightSecretConsumer::IssuanceSigningKey,
        )?;
    }
    for (caller_id, caller) in &environment.callers {
        add_preflight_secret(
            &mut input,
            &environment_file,
            &format!(
                "/callers/{}/api_key_fingerprint/secret",
                escape_explanation_pointer_segment(caller_id)
            ),
            &caller.api_key_fingerprint,
            PreflightSecretConsumer::CallerApiKeyFingerprint,
        )?;
    }
    if let Some(binding) = &environment.notary_relay {
        add_preflight_runtime_file(
            &mut input,
            &environment_file,
            "/notary_relay/token_file",
            &binding.token_file,
            PreflightRuntimeFileKind::NotaryToRelayToken,
        )?;
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
    if let Some(binding) = &environment.notary_state {
        add_preflight_runtime_file(
            &mut input,
            &environment_file,
            "/notary_state/postgresql/root_certificate_path",
            &binding.postgresql.root_certificate_path,
            PreflightRuntimeFileKind::NotaryStateRootCertificate,
        )?;
    }
    if let Some(oid4vci) = &environment.oid4vci {
        for (reference, consumer, pointer) in [
            (
                &oid4vci.client.signing_key,
                PreflightSecretConsumer::Oid4vciClientSigningKey,
                "/oid4vci/client/signing_key/secret",
            ),
            (
                &oid4vci.access_token.signing_key,
                PreflightSecretConsumer::Oid4vciAccessTokenSigningKey,
                "/oid4vci/access_token/signing_key/secret",
            ),
            (
                &oid4vci.sensitive_state_key,
                PreflightSecretConsumer::Oid4vciSensitiveStateKey,
                "/oid4vci/sensitive_state_key/secret",
            ),
        ] {
            add_preflight_secret(&mut input, &environment_file, pointer, reference, consumer)?;
        }
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
    let (fixtures, generated_observations, request_observations, call_budget_actual) =
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
        &request_observations,
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
        None,
        &loaded.project.registry.id,
        &options.environment,
        &artifact_inputs,
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
