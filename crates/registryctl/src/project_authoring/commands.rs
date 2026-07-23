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
            format!("failed to inspect staged project path {}", source_path.display())
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
        assert!(
            fs::read_dir(&destination)
                .expect("destination reads")
                .next()
                .is_none()
        );
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

fn starter_explanation(loaded: &LoadedRegistryProject) -> Value {
    match &loaded.project.starter {
        Some(starter) => json!({
            "id": starter.id,
            "release": starter.release,
            "expected_content_digest": starter.content_digest,
            "current_content_digest": loaded.project_content_digest,
            "state": if starter.content_digest == loaded.project_content_digest {
                "matches"
            } else {
                "diverged"
            },
        }),
        None => json!({ "state": "not_initialized_from_starter" }),
    }
}

pub fn test_registry_project(options: &ProjectTestOptions) -> Result<ProjectCommandReport> {
    test_registry_project_selected(options, &ProjectTestSelection::default())
}

pub fn test_registry_project_selected(
    options: &ProjectTestOptions,
    selection: &ProjectTestSelection,
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
    let mut reports = execute_all_fixtures(
        &loaded,
        &compiled,
        selection.integration.as_deref(),
        selection.fixture.as_deref(),
        selection.trace,
    )?;
    require_passing_fixtures(&reports)?;
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

fn execute_governed_live_test(loaded: &LoadedRegistryProject) -> Result<FixtureReport> {
    let environment = loaded
        .environment_name
        .as_deref()
        .ok_or_else(|| anyhow!("live project tests require an environment"))?;
    if matches!(environment, "prod" | "production")
        || environment.starts_with("prod-")
        || environment.ends_with("-prod")
        || loaded.environment.as_ref().is_some_and(|environment| {
            matches!(
                environment.deployment.profile,
                DeploymentProfile::Production | DeploymentProfile::EvidenceGrade
            )
        })
    {
        bail!("live project tests refuse production environments");
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
    let claims = validate_live_request(loaded, &request)?;
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
    let response = governed_live_evaluation_request(&endpoint, &api_key)
        .send_bytes(&request_bytes)
        .map_err(|_| anyhow!("governed Notary evaluation failed"))?;
    let mut response_bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_LIVE_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_bytes)
        .context("failed to read the governed Notary response")?;
    if response_bytes.len() as u64 > MAX_LIVE_RESPONSE_BYTES {
        bail!("governed Notary response exceeded the configured bound");
    }
    let response = parse_json_strict(&response_bytes)
        .context("governed Notary response was not strict JSON")?;
    let returned_claims = validate_live_response(&response, &claims, &expected)?;
    Ok(governed_live_fixture_report(returned_claims))
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
    requested_claims: &[String],
    expected: &Value,
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
    if results.len() != requested_claims.len() {
        bail!("governed Notary response did not return every requested claim exactly once");
    }
    let requested = requested_claims
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
    for result in results {
        let result_object = result
            .as_object()
            .ok_or_else(|| anyhow!("governed Notary result must be an object"))?;
        if !result_object.contains_key("expires_at") {
            bail!(
                "governed Notary result does not match the closed public claim-result schema: expires_at is required"
            );
        }
        let result_view: registry_notary_core::ClaimResultView =
            serde_json::from_value(result.clone()).map_err(|_| {
                anyhow!(
                    "governed Notary result does not match the closed public claim-result schema"
                )
            })?;
        if !result_view.provenance.derived_from.is_empty() {
            bail!("governed Notary result provenance derived_from must remain empty");
        }
        let generated_by = result
            .pointer("/provenance/generated_by")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow!("governed Notary result has invalid provenance"))?;
        if generated_by.contains_key("pack_id") || generated_by.contains_key("pack_version") {
            bail!("governed Notary result exceeds the closed public claim-result schema");
        }
        let claim_id = result_view.claim_id.as_str();
        if !requested.contains(claim_id) || !returned.insert(claim_id.to_string()) {
            bail!("governed Notary response contains an unknown or duplicate claim result");
        }
        let expected_result = expected[claim_id]
            .as_object()
            .ok_or_else(|| anyhow!("live expected claim result must be an object"))?;
        if expected_result
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["disclosure", "satisfied", "value"])
        {
            bail!(
                "live expected claim result must contain exactly value, satisfied, and disclosure"
            );
        }
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

fn validate_live_request(loaded: &LoadedRegistryProject, request: &Value) -> Result<Vec<String>> {
    let object = request
        .as_object()
        .ok_or_else(|| anyhow!("live request must be a JSON object"))?;
    if contains_sensitive_request_key(request) {
        bail!("live request contains a forbidden credential-like field");
    }
    let purpose = object
        .get("purpose")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("live request must declare one project purpose"))?;
    let services = loaded
        .project
        .services
        .values()
        .filter(|service| service.kind == ServiceKind::Evidence && service.purpose == purpose)
        .collect::<Vec<_>>();
    if services.is_empty() {
        bail!("live request purpose is not declared by this project");
    }
    let claims = object
        .get("claims")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("live request must contain a claims array"))?;
    if claims.is_empty() || claims.len() > MAX_CLAIMS {
        bail!("live request claim count is outside the project bound");
    }
    let mut ids = Vec::with_capacity(claims.len());
    let mut unique = BTreeSet::new();
    for claim in claims {
        let id = match claim {
            Value::String(id) => id.as_str(),
            Value::Object(object) => object
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("live request claim reference is invalid"))?,
            _ => bail!("live request claim reference is invalid"),
        };
        if !services
            .iter()
            .any(|service| service.claims.contains_key(id))
            || !unique.insert(id)
        {
            bail!("live request contains an unknown or duplicate project claim");
        }
        ids.push(id.to_string());
    }
    Ok(ids)
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

pub fn check_registry_project(options: &ProjectCheckOptions) -> Result<ProjectCommandReport> {
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
    let baseline = load_verified_baseline(
        options.against.as_deref(),
        options.anchor.as_deref(),
        &loaded,
    )?;
    let compiled = compile_project(&loaded, baseline.as_ref())?;
    validate_generated_product_configs(&compiled)?;
    let fixtures = execute_all_fixtures(&loaded, &compiled, None, None, false)?;
    require_passing_fixtures(&fixtures)?;
    Ok(ProjectCommandReport {
        schema_version: PROJECT_COMMAND_REPORT_SCHEMA_VERSION,
        status: "valid",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        baseline: if baseline.is_some() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: None,
        explanation: options.explain.then_some(compiled.explanation),
    })
}

pub fn build_registry_project(options: &ProjectBuildOptions) -> Result<ProjectCommandReport> {
    build_registry_project_inner(options, false, None)
}

/// Build the closed local tutorial runtime in one atomic publication.
///
/// These overrides are fixed in reviewed `registryctl` code, are not authored
/// extension input, and are revalidated with the production product models
/// before publication. Applying them before `write_compiled_project` prevents
/// containers from observing the compiler's PostgreSQL defaults between the
/// generated build and the tutorial's in-memory runtime configuration.
pub(crate) fn build_registry_project_for_local_tutorial(
    options: &ProjectBuildOptions,
    runtime_identity: Option<crate::RuntimeIdentity>,
) -> Result<ProjectCommandReport> {
    build_registry_project_inner(options, true, runtime_identity)
}

fn build_registry_project_inner(
    options: &ProjectBuildOptions,
    local_tutorial_runtime: bool,
    runtime_identity: Option<crate::RuntimeIdentity>,
) -> Result<ProjectCommandReport> {
    validate_baseline_pair(options.against.as_deref(), options.anchor.as_deref())?;
    let loaded = load_registry_project(
        &options.project_directory,
        Some(options.environment.as_str()),
    )?;
    preflight_project_rhai_scripts(&loaded)?;
    let baseline = load_verified_baseline(
        options.against.as_deref(),
        options.anchor.as_deref(),
        &loaded,
    )?;
    let mut compiled = compile_project(&loaded, baseline.as_ref())?;
    if local_tutorial_runtime {
        apply_local_tutorial_runtime_overrides(&mut compiled)?;
    }
    validate_generated_product_configs(&compiled)?;
    let fixtures = execute_all_fixtures(&loaded, &compiled, None, None, false)?;
    require_passing_fixtures(&fixtures)?;
    let output = loaded
        .root
        .join(BUILD_ROOT)
        .join(options.environment.as_str());
    write_compiled_project(&loaded.root, &output, &compiled, runtime_identity)?;
    Ok(ProjectCommandReport {
        schema_version: PROJECT_COMMAND_REPORT_SCHEMA_VERSION,
        status: "built",
        project: loaded.project.registry.id.clone(),
        environment: loaded.environment_name.clone(),
        fixtures,
        semantic_changes: compiled.semantic_changes,
        baseline: if baseline.is_some() {
            "verified_signed_bundle"
        } else {
            "initial_without_baseline"
        },
        output: Some(output.display().to_string()),
        explanation: None,
    })
}

fn apply_local_tutorial_runtime_overrides(compiled: &mut CompiledProject) -> Result<()> {
    let notary = compiled
        .notary_private
        .get_mut(Path::new("config/notary.yaml"))
        .ok_or_else(|| anyhow!("generated local Notary config is absent"))?;
    let mut notary_config: serde_norway::Value = serde_norway::from_slice(notary)
        .context("generated local Notary config did not parse")?;
    notary_config["server"]["bind"] =
        serde_norway::Value::String("0.0.0.0:8081".to_string());
    notary_config["state"] = serde_norway::from_str("storage: in_memory\n")?;
    notary_config["evidence"]["signing_keys"] = serde_norway::from_str(&format!(
        "relay-workload:\n  provider: local_jwk_env\n  private_jwk_env: {}\n  alg: EdDSA\n  kid: {}\n  status: active\n",
        super::NOTARY_RELAY_WORKLOAD_JWK_ENV,
        super::NOTARY_RELAY_WORKLOAD_KID,
    ))?;
    *notary = serde_norway::to_string(&notary_config)
        .context("failed to render local Notary config")?
        .into_bytes()
        .into_boxed_slice();

    let relay = compiled
        .relay_private
        .get_mut(Path::new("config/relay.yaml"))
        .ok_or_else(|| anyhow!("generated local consultation Relay config is absent"))?;
    let mut relay_config: serde_norway::Value = serde_norway::from_slice(relay)
        .context("generated local consultation Relay config did not parse")?;
    relay_config["server"]["bind"] =
        serde_norway::Value::String("0.0.0.0:8082".to_string());
    relay_config["auth"]["oidc"]["allow_dev_insecure_fetch_urls"] =
        serde_norway::Value::Bool(true);
    relay_config["consultation"]["state_plane"]["root_certificate_path"] =
        serde_norway::Value::String("/run/registry-tls/state-plane-ca.pem".to_string());
    *relay = serde_norway::to_string(&relay_config)
        .context("failed to render local consultation Relay config")?
        .into_bytes()
        .into_boxed_slice();
    Ok(())
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
