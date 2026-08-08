// SPDX-License-Identifier: Apache-2.0

use crate::dev_credentials::{
    DevCredentialPublicProjection, DevCredentialRequirements, DevOAuthCredentialProfile,
    DevRelayApiKeyRequirements, DevSourceCredentialProfile,
    DevSourceCredentialProjection, PreparedDevCredentialClosure,
};
use crate::dev_runtime::{
    AuthoredDevScenario, AuthoredDevelopment,
    AuthoredLocalSnapshot, AuthoredSyntheticOauthRequest, AuthoredSyntheticSourcePlan,
    AuthoredSyntheticSourceRequest, DevEnvironmentProfile,
    DevOAuthProfile, DevSourceMode, DevSourceProvider, SyntheticOAuthResponseCase,
    SyntheticRequestEncoding, SyntheticRequestMethod, SyntheticSourceAuth, SyntheticSourceScenario,
};
use base64::Engine as _;
use registry_platform_config::{
    ConfigBundleFile, ConfigBundleManifest, ConfigBundleSignature, ConfigBundleSignatureEnvelope,
    ConfigTrustAnchor, ConfigTrustAnchorSigner, ProductAcceptanceIdentityV1,
    ProductAcceptanceLaneV1, ProductAcceptanceProductV1, ProductTrustDomainV1,
};
use registry_platform_crypto::{sign as sign_payload, PrivateJwk, PublicJwk};

const DEV_AUDIT_PSEUDONYM_WRITE_WINDOW_MS: i64 = 30 * 24 * 60 * 60 * 1_000;

/// Validated authoring inputs for the owner-only local development
/// materializer.
///
/// This projection deliberately does not implement `Debug` or `Serialize`.
/// Fixture values and the governed request are retained only long enough for
/// the local runtime to create its owner-only request and synthetic-source
/// inputs. They must never enter reports, logs, or governed evidence.
pub(crate) struct DevAuthoringProjection {
    pub project_id: String,
    pub environment_id: String,
    pub environment_profile: DevEnvironmentProfile,
    pub development: AuthoredDevelopment,
    /// Exact authored source credential environment locators required by an
    /// operator-bound consultation Relay. Sorted and deduplicated. Empty for
    /// synthetic development.
    pub operator_source_secret_env: Vec<String>,
    pub scenarios: Vec<AuthoredDevScenario>,
    pub records_request: Option<AuthoredRecordsRequest>,
    pub local_snapshot: Option<AuthoredLocalSnapshot>,
    credential_requirements: DevCredentialRequirements,
}

/// Exact, validated public Relay records request selected from authoring.
///
/// This is kept out of reports and persisted plans because its record id is
/// an authored principal identifier. It exists only long enough to create the
/// owner-only curl configuration.
pub(crate) struct AuthoredRecordsRequest {
    pub(crate) dataset_id: String,
    pub(crate) entity_id: String,
    pub(crate) record_id: String,
    pub(crate) purpose: String,
    scopes: [String; 2],
}

/// Value-free projection applied only to the in-memory development compile.
///
/// It deliberately does not implement `Debug` or `Serialize`. Although every
/// field is nonsecret, keeping it opaque prevents it from becoming another
/// persistent authoring or deployment contract.
pub(crate) struct DevBindingProjection {
    pub project_id: String,
    pub environment_id: String,
    pub source_mode: DevSourceMode,
    pub integration_id: String,
    pub entity_id: Option<String>,
    pub synthetic_source_origin: Option<String>,
    pub credentials: DevCredentialPublicProjection,
    pub trust_domain: ProductTrustDomainV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledSignedDevLanes {
    pub relay_public_bundle: PathBuf,
    pub relay_public_anchor: PathBuf,
    pub relay_consultation_bundle: PathBuf,
    pub relay_consultation_anchor: PathBuf,
    /// Relay public and Relay consultation, in that order.
    pub lane_config_digests: [String; 2],
}

impl DevAuthoringProjection {
    pub(crate) fn credential_requirements(&self) -> DevCredentialRequirements {
        self.credential_requirements.clone()
    }
}

/// Load and validate the authored development scenario without inventing a
/// default or resolving any generated credential.
pub(crate) fn compile_dev_runtime_authoring(
    project_directory: &Path,
    environment_id: &str,
) -> Result<DevAuthoringProjection> {
    prevalidate_development_required_fields(project_directory, environment_id)?;
    let loaded = load_registry_project(project_directory, Some(environment_id))?;
    let environment = loaded
        .environment
        .as_ref()
        .ok_or_else(|| anyhow!("environments/{environment_id}.yaml# is not selected"))?;
    let development = environment.development.as_ref().ok_or_else(|| {
        anyhow!("environments/{environment_id}.yaml#/development is required for registryctl dev")
    })?;
    let source_mode = development.source_mode;
    let default_integration = development.default_integration.as_str();
    validate_stable_id(default_integration, "development.default_integration").with_context(
        || {
            format!(
                "environments/{environment_id}.yaml#/development/default_integration is invalid"
            )
        },
    )?;
    let default_fixture = development.default_fixture.as_str();
    validate_stable_id(default_fixture, "development.default_fixture").with_context(|| {
        format!("environments/{environment_id}.yaml#/development/default_fixture is invalid")
    })?;
    validate_development_ports(environment_id, development)?;

    let available = available_development_scenarios(&loaded);
    let selected_id = format!("{default_integration}.{default_fixture}");
    let Some((integration, fixture)) =
        selected_development_fixture(&loaded, default_integration, default_fixture)
    else {
        bail!(
            "environments/{environment_id}.yaml#/development/default_integration and environments/{environment_id}.yaml#/development/default_fixture select {selected_id}, which is not an authored scenario; available scenario ids: {}",
            available.join(", ")
        );
    };
    let fixture_relative = fixture
        .0
        .strip_prefix(&loaded.root)
        .unwrap_or(&fixture.0)
        .to_string_lossy();
    let fixture_document = &fixture.1;
    if fixture_document.interactions.len() != 1 {
        bail!(
            "{fixture_relative}#/interactions must contain exactly one interaction for the closed development source profile"
        );
    }

    let operator_source_binding_present = validate_development_source_mode(
        environment_id,
        default_integration,
        source_mode,
        environment,
        integration,
    )?;
    let operator_source_secret_env =
        operator_source_secret_env(environment, default_integration, source_mode);
    let local_snapshot = development_local_snapshot(&loaded, integration, source_mode)?;
    let (source_provider, credential) = development_provider_and_credential(integration);
    let integration_file = loaded.project.integrations[default_integration]
        .file
        .to_string_lossy();
    let (request_encoding, oauth_profile, source_auth, oauth_request) =
        compile_development_auth(&integration_file, credential)?;
    let records_request = select_development_records_request(&loaded, environment_id)?;
    let credential_requirements = development_credential_requirements(
        DevelopmentCredentialRequirementsInput {
            loaded: &loaded,
            environment_id,
            integration_id: default_integration,
            source_mode,
            credential,
            relay_api_key_scopes: records_request
                .as_ref()
                .map(|request| request.scopes.as_slice()),
        },
    )?;
    let interaction = &fixture_document.interactions[0];
    let source_request = compile_synthetic_source_request(&fixture_relative, &interaction.expect)?;
    let (scenario, response_body) = compile_synthetic_source_response(
        &fixture_relative,
        fixture_document,
        &interaction.respond,
    )?;
    let synthetic_source =
        (source_mode == DevelopmentSourceMode::Synthetic).then(|| AuthoredSyntheticSourcePlan {
            scenario,
            source_request,
            source_auth,
            oauth_response_case: (oauth_profile != DevOAuthProfile::None)
                .then_some(SyntheticOAuthResponseCase::Valid),
            oauth_request,
            response_body,
        });
    let scenario = AuthoredDevScenario {
        integration_id: default_integration.to_owned(),
        fixture_id: default_fixture.to_owned(),
        synthetic: fixture_document.classification == AuthoredFixtureClassification::Synthetic,
        source_provider,
        request_encoding,
        oauth_profile,
        denial_scenario_id: "unauthorized".to_string(),
        authorized_scenario_id: "authorized".to_string(),
        synthetic_source,
    };

    Ok(DevAuthoringProjection {
        project_id: loaded.project.registry.id,
        environment_id: environment_id.to_owned(),
        environment_profile: development_environment_profile(environment.deployment.profile),
        development: AuthoredDevelopment {
            source_mode: development_source_mode(source_mode),
            default_integration: default_integration.to_owned(),
            default_fixture: default_fixture.to_owned(),
            operator_source_binding_present,
            relay_port: development.relay_port,
        },
        operator_source_secret_env,
        scenarios: vec![scenario],
        records_request,
        local_snapshot,
        credential_requirements,
    })
}

fn select_development_records_request(
    loaded: &LoadedRegistryProject,
    environment_id: &str,
) -> Result<Option<AuthoredRecordsRequest>> {
    let environment = loaded
        .environment
        .as_ref()
        .expect("selected environment was loaded");
    let Some(local_keys) = environment
        .relay
        .as_ref()
        .and_then(|relay| relay.local_api_keys.as_ref())
    else {
        return Ok(None);
    };

    let snapshot_entities = loaded
        .integrations
        .values()
        .filter_map(|integration| match &integration.document.capability {
            CapabilityDeclaration::Snapshot { snapshot } => Some(snapshot.entity.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut candidates = loaded
        .project
        .services
        .iter()
        .filter_map(|(service_id, service)| {
            let entity = service.entity.as_deref()?;
            let api = service.api.as_ref()?;
            let primary_key = loaded
                .entities
                .get(entity)
                .map(|entity| entity.document.primary_key.as_str())?;
            (service.kind == ServiceKind::RecordsApi
                && snapshot_entities.contains(entity)
                && local_keys.scopes.contains(&api.scopes.metadata)
                && local_keys.scopes.contains(&api.scopes.rows)
                && api.required_principal_filters.as_slice() == [primary_key])
            .then_some((service_id.as_str(), entity, api))
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        bail!(
            "environments/{environment_id}.yaml#/relay/local_api_keys requires one exact snapshot records service whose metadata and rows scopes are granted and whose sole principal-bound filter is the entity primary key; matching service ids: {}",
            candidates
                .iter()
                .map(|(service_id, _, _)| *service_id)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let (service_id, entity_id, api) = candidates.remove(0);
    if api.purposes.len() != 1 {
        bail!(
            "registry-stack.yaml#/services/{service_id}/api/purposes must contain exactly one purpose for the development records request"
        );
    }
    Ok(Some(AuthoredRecordsRequest {
        dataset_id: entity_id.to_string(),
        entity_id: entity_id.to_string(),
        record_id: local_keys.match_principal.clone(),
        purpose: api.purposes[0].clone(),
        scopes: [api.scopes.metadata.clone(), api.scopes.rows.clone()],
    }))
}

fn operator_source_secret_env(
    environment: &EnvironmentDocument,
    integration_id: &str,
    source_mode: DevelopmentSourceMode,
) -> Vec<String> {
    if source_mode != DevelopmentSourceMode::OperatorBound {
        return Vec::new();
    }
    let Some(credential) = environment
        .integrations
        .get(integration_id)
        .and_then(|integration| integration.source.credential.as_ref())
    else {
        return Vec::new();
    };
    [
        credential.username.as_ref(),
        credential.password.as_ref(),
        credential.token.as_ref(),
        credential.client_id.as_ref(),
        credential.client_secret.as_ref(),
        credential.value.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|reference| reference.secret.clone())
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

struct DevelopmentCredentialRequirementsInput<'a> {
    loaded: &'a LoadedRegistryProject,
    environment_id: &'a str,
    integration_id: &'a str,
    source_mode: DevelopmentSourceMode,
    credential: &'a CredentialInterface,
    relay_api_key_scopes: Option<&'a [String]>,
}

fn development_credential_requirements(
    input: DevelopmentCredentialRequirementsInput<'_>,
) -> Result<DevCredentialRequirements> {
    let DevelopmentCredentialRequirementsInput {
        loaded,
        environment_id,
        integration_id,
        source_mode,
        credential,
        relay_api_key_scopes,
    } = input;
    let environment = loaded
        .environment
        .as_ref()
        .expect("selected environment was loaded");
    let source = if matches!(
        source_mode,
        DevelopmentSourceMode::OperatorBound | DevelopmentSourceMode::LocalSnapshot
    ) {
        DevSourceCredentialProfile::OperatorBound
    } else {
        let binding = environment
            .integrations
            .get(integration_id)
            .and_then(|integration| integration.source.credential.as_ref());
        match credential.credential_type {
            CredentialType::None => DevSourceCredentialProfile::SyntheticUnauthenticated,
            CredentialType::StaticBearer => {
                let relay_token_env = binding
                    .and_then(|credential| credential.token.as_ref())
                    .map(|secret| secret.secret.clone())
                    .ok_or_else(|| {
                        anyhow!(
                            "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential/token is required"
                        )
                    })?;
                DevSourceCredentialProfile::SyntheticStaticBearer { relay_token_env }
            }
            CredentialType::Oauth2ClientCredentials => {
                let binding = binding.ok_or_else(|| {
                    anyhow!(
                        "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential is required"
                    )
                })?;
                let relay_client_id_env = binding
                    .client_id
                    .as_ref()
                    .map(|secret| secret.secret.clone())
                    .ok_or_else(|| {
                        anyhow!(
                            "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential/client_id is required"
                        )
                    })?;
                let relay_client_secret_env = binding
                    .client_secret
                    .as_ref()
                    .map(|secret| secret.secret.clone())
                    .ok_or_else(|| {
                        anyhow!(
                            "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential/client_secret is required"
                        )
                    })?;
                let profile = match credential.response_profile {
                    Some(OAuthResponseProfile::Oauth2Bearer) => {
                        DevOAuthCredentialProfile::Oauth2Bearer
                    }
                    Some(OAuthResponseProfile::Oauth2BearerNoExpiry) => {
                        DevOAuthCredentialProfile::Oauth2BearerNoExpiry
                    }
                    None => {
                        bail!(
                            "the selected OAuth development integration lacks its response profile"
                        )
                    }
                };
                DevSourceCredentialProfile::SyntheticOAuthClientCredentials {
                    profile,
                    relay_client_id_env,
                    relay_client_secret_env,
                }
            }
            CredentialType::Basic | CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
                bail!("the selected source credential is outside the closed development profile")
            }
        }
    };
    Ok(DevCredentialRequirements {
        project_id: loaded.project.registry.id.clone(),
        environment_id: environment_id.to_owned(),
        relay_api_keys: match (
            environment
                .relay
                .as_ref()
                .and_then(|relay| relay.local_api_keys.as_ref()),
            relay_api_key_scopes,
        ) {
            (Some(keys), Some(scopes)) => Some(DevRelayApiKeyRequirements {
                match_principal: keys.match_principal.clone(),
                no_match_principal: keys.no_match_principal.clone(),
                scopes: scopes.to_vec(),
            }),
            (None, None) => None,
            _ => bail!("development Relay API-key scopes do not match the selected records request"),
        },
        source,
    })
}

fn prevalidate_development_required_fields(
    project_directory: &Path,
    environment_id: &str,
) -> Result<()> {
    validate_stable_id(environment_id, "environment")?;
    let root = canonical_root(project_directory)?;
    let relative = PathBuf::from("environments").join(format!("{environment_id}.yaml"));
    let path = resolve_authored_path(&root, &relative)?;
    let bytes = read_authored_file(&root, &path)?;
    let value: Value = serde_norway::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", relative.display()))?;
    let development = value.get("development").ok_or_else(|| {
        anyhow!("environments/{environment_id}.yaml#/development is required for registryctl dev")
    })?;
    let development = development.as_object().ok_or_else(|| {
        anyhow!("environments/{environment_id}.yaml#/development must be a closed object")
    })?;
    for field in ["source_mode", "default_integration", "default_fixture"] {
        if !development.contains_key(field) {
            bail!("environments/{environment_id}.yaml#/development/{field} is required");
        }
    }
    Ok(())
}

fn validate_development_ports(
    environment_id: &str,
    development: &DevelopmentDeclaration,
) -> Result<()> {
    if development.relay_port == Some(0) {
        bail!("environments/{environment_id}.yaml#/development/relay_port must be non-zero");
    }
    Ok(())
}

fn available_development_scenarios(loaded: &LoadedRegistryProject) -> Vec<String> {
    let mut scenarios = loaded
        .integrations
        .iter()
        .flat_map(|(alias, integration)| {
            integration
                .fixtures
                .iter()
                .map(move |(_, fixture)| format!("{alias}.{}", fixture.name))
        })
        .collect::<Vec<_>>();
    scenarios.sort();
    scenarios
}

fn selected_development_fixture<'a>(
    loaded: &'a LoadedRegistryProject,
    integration_id: &str,
    fixture_id: &str,
) -> Option<(&'a LoadedIntegration, &'a (PathBuf, FixtureDocument))> {
    let integration = loaded.integrations.get(integration_id)?;
    let fixture = integration
        .fixtures
        .iter()
        .find(|(_, fixture)| fixture.name == fixture_id)?;
    Some((integration, fixture))
}

fn validate_development_source_mode(
    environment_id: &str,
    integration_id: &str,
    source_mode: DevelopmentSourceMode,
    environment: &EnvironmentDocument,
    integration: &LoadedIntegration,
) -> Result<bool> {
    let operator_binding_present = match &integration.document.capability {
        CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => {
            environment
                .integrations
                .get(integration_id)
                .ok_or_else(|| {
                    anyhow!(
                        "environments/{environment_id}.yaml#/integrations/{integration_id} is missing the selected source binding"
                    )
                })?;
            true
        }
        CapabilityDeclaration::Snapshot { snapshot } => {
            environment.entities.contains_key(&snapshot.entity)
        }
    };
    match source_mode {
        DevelopmentSourceMode::Synthetic => {
            if matches!(
                integration.document.capability,
                CapabilityDeclaration::Snapshot { .. }
            ) {
                bail!(
                    "environments/{environment_id}.yaml#/development/source_mode must be local_snapshot for a spreadsheet integration"
                );
            }
            Ok(false)
        }
        DevelopmentSourceMode::LocalSnapshot => {
            let CapabilityDeclaration::Snapshot { snapshot } = &integration.document.capability
            else {
                bail!(
                    "environments/{environment_id}.yaml#/development/source_mode is local_snapshot but the selected integration is not a snapshot"
                );
            };
            let binding = environment.entities.get(&snapshot.entity).ok_or_else(|| {
                anyhow!(
                    "environments/{environment_id}.yaml#/entities/{} is missing the selected snapshot binding",
                    snapshot.entity
                )
            })?;
            if !matches!(binding.provider, RecordProvider::Xlsx { .. }) {
                bail!(
                    "environments/{environment_id}.yaml#/entities/{}/provider is not a contained XLSX project file",
                    snapshot.entity
                );
            }
            Ok(false)
        }
        DevelopmentSourceMode::OperatorBound => {
            if !operator_binding_present {
                bail!(
                    "environments/{environment_id}.yaml#/development/source_mode is operator_bound but the selected integration has no explicit operator source binding"
                );
            }
            Ok(true)
        }
    }
}

fn development_local_snapshot(
    loaded: &LoadedRegistryProject,
    integration: &LoadedIntegration,
    source_mode: DevelopmentSourceMode,
) -> Result<Option<AuthoredLocalSnapshot>> {
    if source_mode != DevelopmentSourceMode::LocalSnapshot {
        return Ok(None);
    }
    let CapabilityDeclaration::Snapshot { snapshot } = &integration.document.capability else {
        bail!("local snapshot development lost its validated snapshot integration");
    };
    let binding = loaded
        .environment
        .as_ref()
        .and_then(|environment| environment.entities.get(&snapshot.entity))
        .ok_or_else(|| anyhow!("local snapshot development lost its validated entity binding"))?;
    let RecordProvider::Xlsx {
        project_file, path, ..
    } = &binding.provider
    else {
        bail!("local snapshot development lost its validated XLSX provider");
    };
    let host_path = std::fs::canonicalize(loaded.root.join(project_file))
        .context("local snapshot project file cannot be resolved")?;
    if !host_path.starts_with(&loaded.root) || !host_path.is_file() {
        bail!("local snapshot project file must be a regular file contained by the project");
    }
    let container_path = path
        .to_str()
        .ok_or_else(|| anyhow!("local snapshot runtime path is not Unicode"))?
        .to_string();
    let digest = registry_platform_config::sha256_uri(
        &crate::dev_runtime::read_bounded_regular_file(
            &host_path,
            crate::dev_runtime::MAX_LOCAL_SNAPSHOT_BYTES,
        )
        .context("local snapshot project file is unsafe, unreadable, or too large")?,
    );
    Ok(Some(AuthoredLocalSnapshot {
        host_path,
        container_path,
        digest,
    }))
}

fn development_provider_and_credential(
    integration: &LoadedIntegration,
) -> (DevSourceProvider, &CredentialInterface) {
    match &integration.document.capability {
        CapabilityDeclaration::Http { http } => (DevSourceProvider::Http, &http.credential),
        CapabilityDeclaration::Script { script } => (DevSourceProvider::Rhai, &script.credential),
        CapabilityDeclaration::Snapshot { .. } => (
            DevSourceProvider::Spreadsheet,
            // Snapshot sources are local provider bindings and do not carry a
            // remote-source credential interface.
            &NO_DEVELOPMENT_CREDENTIAL,
        ),
    }
}

static NO_DEVELOPMENT_CREDENTIAL: CredentialInterface = CredentialInterface {
    credential_type: CredentialType::None,
    name: None,
    max_value_bytes: None,
    request: None,
    response_profile: None,
    scope: None,
    audience: None,
    refresh_skew: None,
};

fn compile_development_auth(
    integration_file: &str,
    credential: &CredentialInterface,
) -> Result<(
    SyntheticRequestEncoding,
    DevOAuthProfile,
    Option<SyntheticSourceAuth>,
    Option<AuthoredSyntheticOauthRequest>,
)> {
    match credential.credential_type {
        CredentialType::None => Ok((
            SyntheticRequestEncoding::Json,
            DevOAuthProfile::None,
            None,
            None,
        )),
        CredentialType::StaticBearer => Ok((
            SyntheticRequestEncoding::Json,
            DevOAuthProfile::None,
            Some(SyntheticSourceAuth::StaticBearer),
            None,
        )),
        CredentialType::Oauth2ClientCredentials => {
            let encoding = match credential.request.ok_or_else(|| {
                anyhow!("{integration_file}#/source/auth/request is required for OAuth development")
            })? {
                OAuthRequestFormat::Json => SyntheticRequestEncoding::Json,
                OAuthRequestFormat::Form => SyntheticRequestEncoding::Form,
            };
            let profile = match credential.response_profile.ok_or_else(|| {
                anyhow!(
                    "{integration_file}#/source/auth/response_profile is required for OAuth development"
                )
            })? {
                OAuthResponseProfile::Oauth2Bearer => DevOAuthProfile::Oauth2Bearer,
                OAuthResponseProfile::Oauth2BearerNoExpiry => {
                    DevOAuthProfile::Oauth2BearerNoExpiry
                }
            };
            Ok((
                encoding,
                profile,
                None,
                Some(AuthoredSyntheticOauthRequest {
                    audience: credential.audience.clone(),
                    scope: credential.scope.clone(),
                    resource: None,
                }),
            ))
        }
        CredentialType::Basic | CredentialType::ApiKeyHeader | CredentialType::ApiKeyQuery => {
            bail!(
                "{integration_file}#/source/auth/type uses a credential type unsupported by the closed development profile; accepted values: none, static_bearer, oauth2_client_credentials"
            )
        }
    }
}

fn compile_synthetic_source_request(
    fixture_file: &str,
    request: &FixtureRequestExpectation,
) -> Result<AuthoredSyntheticSourceRequest> {
    let method = match request.method {
        ReadMethod::Get => SyntheticRequestMethod::Get,
        ReadMethod::Post => SyntheticRequestMethod::Post,
    };
    let mut query = BTreeMap::new();
    for (name, value) in &request.query {
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            Value::Null | Value::Array(_) | Value::Object(_) => {
                bail!(
                    "{fixture_file}#/interactions/0/expect/query/{name} cannot be materialized as one exact wire scalar"
                )
            }
        };
        query.insert(name.clone(), value);
    }
    let mut headers = BTreeMap::new();
    for (name, value) in &request.headers {
        if name != &name.to_ascii_lowercase() || name.eq_ignore_ascii_case("authorization") {
            bail!(
                "{fixture_file}#/interactions/0/expect/headers/{name} must be lowercase and cannot author an authorization credential"
            );
        }
        headers.insert(name.clone(), value.clone());
    }
    Ok(AuthoredSyntheticSourceRequest {
        method,
        path: request.path.clone(),
        query,
        headers,
        body: request.body.clone(),
    })
}

fn compile_synthetic_source_response(
    fixture_file: &str,
    fixture: &FixtureDocument,
    response: &FixtureSourceResponse,
) -> Result<(SyntheticSourceScenario, Option<Vec<u8>>)> {
    match response {
        FixtureSourceResponse::Timeout { .. } => Ok((SyntheticSourceScenario::SourceTimeout, None)),
        FixtureSourceResponse::Http { status, body, .. } => {
            let scenario = if fixture.expect.error.as_deref() == Some("failure.subject_mismatch") {
                SyntheticSourceScenario::SubjectMismatch
            } else {
                match fixture.expect.outcome.as_deref() {
                    Some("no_match") => SyntheticSourceScenario::NoMatch,
                    Some("ambiguous") => SyntheticSourceScenario::Ambiguity,
                    _ if *status >= 400 => SyntheticSourceScenario::SourceRejected,
                    _ => SyntheticSourceScenario::AuthoredResponse,
                }
            };
            let response_body = if matches!(
                scenario,
                SyntheticSourceScenario::SourceRejected
                    | SyntheticSourceScenario::SourceMalformed
                    | SyntheticSourceScenario::SourceTimeout
                    | SyntheticSourceScenario::SourceOversize
            ) {
                None
            } else {
                Some(serde_json::to_vec(body).with_context(|| {
                    format!("{fixture_file}#/interactions/0/respond/body is invalid")
                })?)
            };
            Ok((scenario, response_body))
        }
    }
}

const fn development_source_mode(source_mode: DevelopmentSourceMode) -> DevSourceMode {
    match source_mode {
        DevelopmentSourceMode::Synthetic => DevSourceMode::Synthetic,
        DevelopmentSourceMode::LocalSnapshot => DevSourceMode::LocalSnapshot,
        DevelopmentSourceMode::OperatorBound => DevSourceMode::OperatorBound,
    }
}

const fn development_environment_profile(profile: DeploymentProfile) -> DevEnvironmentProfile {
    match profile {
        DeploymentProfile::Local => DevEnvironmentProfile::Local,
        DeploymentProfile::HostedLab => DevEnvironmentProfile::HostedLab,
        DeploymentProfile::Production => DevEnvironmentProfile::Production,
    }
}

impl DevBindingProjection {
    fn from_authoring(
        authoring: &DevAuthoringProjection,
        credentials: &DevCredentialPublicProjection,
        entity_id: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            project_id: authoring.project_id.clone(),
            environment_id: authoring.environment_id.clone(),
            source_mode: authoring.development.source_mode,
            integration_id: authoring.development.default_integration.clone(),
            entity_id,
            synthetic_source_origin: (authoring.development.source_mode
                == DevSourceMode::Synthetic)
                .then(|| crate::dev_runtime::DEV_SYNTHETIC_SOURCE_ORIGIN.to_string()),
            credentials: credentials.clone(),
            trust_domain: ProductTrustDomainV1::Development,
        })
    }

    fn apply(&self, loaded: &mut LoadedRegistryProject) -> Result<()> {
        if loaded.project.registry.id != self.project_id
            || loaded.environment_name.as_deref() != Some(self.environment_id.as_str())
            || self.trust_domain != ProductTrustDomainV1::Development
        {
            bail!("development binding projection does not match the validated project selection");
        }
        let environment = loaded
            .environment
            .as_mut()
            .ok_or_else(|| anyhow!("development binding projection lacks its environment"))?;

        let relay = environment
            .relay
            .as_mut()
            .ok_or_else(|| anyhow!("development Relay binding is absent"))?;
        relay.local_api_keys = self.credentials.relay_api_keys.as_ref().map(|keys| {
            RelayLocalApiKeyBinding {
                match_principal: keys.match_principal.clone(),
                no_match_principal: keys.no_match_principal.clone(),
                scopes: keys.scopes.clone(),
            }
        });

        environment.relay_state = Some(RelayStateBinding {
            postgresql: RelayPostgresqlBinding {
                root_certificate_path: PathBuf::from(
                    &self.credentials.databases.root_certificate_path,
                ),
            },
        });
        if let Some(origin) = self
            .synthetic_source_origin
            .as_ref()
            .filter(|_| self.entity_id.is_none())
        {
            let selected = environment
                .integrations
                .get_mut(&self.integration_id)
                .ok_or_else(|| anyhow!("selected development integration binding is absent"))?;
            let transport = self
                .credentials
                .synthetic_source_transport
                .as_ref()
                .ok_or_else(|| anyhow!("synthetic development transport binding is absent"))?;
            selected.source.origin = origin.clone();
            selected.source.allowed_private_cidrs = vec![transport.allowed_private_cidr.clone()];
            selected.source.ca = Some(CertificateAuthorityBinding {
                file: PathBuf::from(&transport.root_certificate_path),
                generation: 1,
            });
            selected.source.mtls = None;
            if let Some(oauth) = selected.source.oauth.as_mut() {
                oauth.origin = origin.clone();
                oauth.path = "/oauth/token".to_string();
                oauth.allowed_private_cidrs = vec![transport.allowed_private_cidr.clone()];
                oauth.ca = Some(CertificateAuthorityBinding {
                    file: PathBuf::from(&transport.root_certificate_path),
                    generation: 1,
                });
                oauth.mtls = None;
            }
            apply_source_credential_projection(
                &self.environment_id,
                &self.integration_id,
                &mut selected.source,
                &self.credentials.source,
            )?;
        } else if matches!(
            self.source_mode,
            DevSourceMode::OperatorBound | DevSourceMode::LocalSnapshot
        )
            && !matches!(
                self.credentials.source,
                DevSourceCredentialProjection::OperatorBound
            )
        {
            bail!("non-synthetic development cannot consume generated source credentials");
        } else if self.entity_id.is_some()
            && self.source_mode == DevSourceMode::Synthetic
            && !matches!(
                self.credentials.source,
                DevSourceCredentialProjection::SyntheticUnauthenticated { .. }
            )
        {
            bail!("synthetic snapshot development cannot bind a remote source credential");
        }

        if let Some(entity_id) = &self.entity_id {
            let entity = environment
                .entities
                .get(entity_id)
                .ok_or_else(|| anyhow!("selected development entity binding is absent"))?;
            if self.source_mode == DevSourceMode::LocalSnapshot
                && !matches!(entity.provider, RecordProvider::Xlsx { .. })
            {
                bail!("local snapshot development requires a contained XLSX source");
            }
        }
        Ok(())
    }
}

fn apply_source_credential_projection(
    environment_id: &str,
    integration_id: &str,
    source: &mut EnvironmentSourceBinding,
    projection: &DevSourceCredentialProjection,
) -> Result<()> {
    match projection {
        DevSourceCredentialProjection::OperatorBound => {
            bail!("synthetic development received an operator-bound source credential")
        }
        DevSourceCredentialProjection::SyntheticUnauthenticated { .. } => {
            source.credential = None;
        }
        DevSourceCredentialProjection::SyntheticStaticBearer {
            relay_token_env, ..
        } => {
            let credential = source.credential.as_mut().ok_or_else(|| {
                anyhow!(
                    "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential is required"
                )
            })?;
            credential.username = None;
            credential.password = None;
            credential.client_id = None;
            credential.client_secret = None;
            credential.value = None;
            credential.token = Some(SecretReference {
                secret: relay_token_env.clone(),
            });
        }
        DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
            relay_client_id_env,
            relay_client_secret_env,
            ..
        } => {
            let credential = source.credential.as_mut().ok_or_else(|| {
                anyhow!(
                    "environments/{environment_id}.yaml#/integrations/{integration_id}/source/credential is required"
                )
            })?;
            credential.username = None;
            credential.password = None;
            credential.token = None;
            credential.value = None;
            credential.client_id = Some(SecretReference {
                secret: relay_client_id_env.clone(),
            });
            credential.client_secret = Some(SecretReference {
                secret: relay_client_secret_env.clone(),
            });
        }
    }
    Ok(())
}

/// Compile the normally validated authored project into three disposable
/// development lanes, bind only generated public credential references, then
/// create and self-verify one fresh signed bundle and anchor per lane.
pub(crate) fn compile_and_sign_dev_lanes(
    project_directory: &Path,
    environment_id: &str,
    credentials: &PreparedDevCredentialClosure,
    output_root: &Path,
) -> Result<CompiledSignedDevLanes> {
    let authoring = compile_dev_runtime_authoring(project_directory, environment_id)?;
    let mut loaded = load_registry_project(project_directory, Some(environment_id))?;
    let entity_id = loaded
        .integrations
        .get(&authoring.development.default_integration)
        .and_then(|integration| match &integration.document.capability {
            CapabilityDeclaration::Snapshot { snapshot } => Some(snapshot.entity.clone()),
            CapabilityDeclaration::Http { .. } | CapabilityDeclaration::Script { .. } => None,
        });
    let projection = DevBindingProjection::from_authoring(
        &authoring,
        credentials.public_projection(),
        entity_id,
    )?;
    projection.apply(&mut loaded)?;
    let environment = loaded
        .environment
        .as_ref()
        .expect("development projection retained the selected environment");
    let mut compiled = compile_project_for_environment(&loaded, environment_id, environment, None)?;
    inject_development_bootstrap(
        &mut compiled.relay_consultation_private,
        &projection.credentials,
    )?;

    let relative_output = output_root
        .strip_prefix(&loaded.root)
        .or_else(|_| output_root.strip_prefix(project_directory))
        .map_err(|_| {
            anyhow!("development signed-lane output must remain under the project root")
        })?;
    validate_relative_authored_path(relative_output)?;
    if !relative_output.starts_with(Path::new(".registry-stack/dev-artifacts")) {
        bail!("development signed-lane output must remain under .registry-stack/dev-artifacts");
    }
    let output_root = loaded.root.join(relative_output);
    let output_root = output_root.as_path();
    reject_symlink_components(&loaded.root, output_root)?;
    if output_root.exists() {
        bail!(
            "development signed-lane output already exists: {}",
            output_root.display()
        );
    }
    create_dir_owner_only(output_root)?;
    let result = write_signed_development_lanes(output_root, &projection, &compiled, credentials);
    if result.is_err() {
        let _ = fs::remove_dir_all(output_root);
    }
    result
}

fn inject_development_bootstrap(
    files: &mut BTreeMap<PathBuf, Box<[u8]>>,
    credentials: &DevCredentialPublicProjection,
) -> Result<()> {
    let active_write_deadline_unix_ms = development_active_write_deadline_unix_ms()?;
    let path = PathBuf::from("config/relay.yaml");
    let bytes = files
        .get(&path)
        .ok_or_else(|| anyhow!("compiled consultation Relay config is absent"))?;
    let mut config: Value =
        serde_norway::from_slice(bytes).context("failed to parse compiled consultation config")?;
    let consultation = config
        .get_mut("consultation")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("compiled consultation Relay policy is absent"))?;
    consultation.insert(
        "bootstrap".to_string(),
        json!({
            "migration_database_url_env": credentials.databases.relay_migration_database_env,
            "owner_role": credentials.databases.relay_owner_role,
            "keyring_maintenance_database_url_env": credentials.databases.relay_maintenance_database_env,
            "keyring_reader_database_url_env": credentials.databases.relay_reader_database_env,
            "active_key_id": "epoch-1",
            "active_write_deadline_unix_ms": active_write_deadline_unix_ms,
            "audit_event_retention_ms": 86_400_000_i64,
        }),
    );
    let rendered = serde_norway::to_string(&config)
        .context("failed to render bound consultation Relay config")?
        .into_bytes()
        .into_boxed_slice();
    files.insert(path, rendered);
    Ok(())
}

fn development_active_write_deadline_unix_ms() -> Result<i64> {
    let now_unix_ms = OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or_else(|| anyhow!("development bundle clock is outside the supported range"))?;
    now_unix_ms
        .checked_add(DEV_AUDIT_PSEUDONYM_WRITE_WINDOW_MS)
        .ok_or_else(|| anyhow!("development audit-pseudonym write deadline overflowed"))
}

fn write_signed_development_lanes(
    output_root: &Path,
    projection: &DevBindingProjection,
    compiled: &CompiledProject,
    credentials: &PreparedDevCredentialClosure,
) -> Result<CompiledSignedDevLanes> {
    let relay_public = sign_development_lane(
        output_root,
        projection,
        credentials,
        ProductAcceptanceLaneV1::RelayPublic,
        ProductAcceptanceProductV1::RegistryRelay,
        "relay-public",
        &compiled.relay_private,
    )?;
    let relay_consultation = sign_development_lane(
        output_root,
        projection,
        credentials,
        ProductAcceptanceLaneV1::RelayConsultation,
        ProductAcceptanceProductV1::RegistryRelay,
        "relay-consultation",
        &compiled.relay_consultation_private,
    )?;
    Ok(CompiledSignedDevLanes {
        relay_public_bundle: relay_public.0,
        relay_public_anchor: relay_public.1,
        relay_consultation_bundle: relay_consultation.0,
        relay_consultation_anchor: relay_consultation.1,
        lane_config_digests: [relay_public.2, relay_consultation.2],
    })
}

fn sign_development_lane(
    output_root: &Path,
    projection: &DevBindingProjection,
    credentials: &PreparedDevCredentialClosure,
    lane: ProductAcceptanceLaneV1,
    product: ProductAcceptanceProductV1,
    instance: &str,
    files: &BTreeMap<PathBuf, Box<[u8]>>,
) -> Result<(PathBuf, PathBuf, String)> {
    if files.is_empty() {
        bail!("development lane {lane:?} compiled an empty closure");
    }
    let signer = projection
        .credentials
        .lane_signers
        .iter()
        .find(|signer| signer.lane == lane)
        .ok_or_else(|| anyhow!("generated credentials lack the selected development lane"))?;
    let public_jwk =
        PublicJwk::parse(&signer.public_jwk).context("development lane public JWK is invalid")?;
    let signer_kid = public_jwk
        .jkt()
        .context("failed to identify development lane public JWK")?;
    if signer.kid != signer_kid {
        bail!("development lane signer id does not match its public JWK thumbprint");
    }
    let identity = ProductAcceptanceIdentityV1 {
        trust_domain: projection.trust_domain,
        project: projection.project_id.clone(),
        environment: projection.environment_id.clone(),
        lane,
        product,
        stream: projection.project_id.clone(),
        instance: instance.to_string(),
    };
    identity
        .validate()
        .context("development lane identity is invalid")?;
    let anchor = ConfigTrustAnchor {
        schema: "registry.platform.config_trust_anchor.v1".to_string(),
        acceptance_identity: identity.clone(),
        version: 1,
        threshold: 1,
        enabled_signers: vec![ConfigTrustAnchorSigner {
            kid: signer_kid.clone(),
            jwk: public_jwk,
        }],
    };
    anchor
        .validate_initial()
        .context("development trust anchor is invalid")?;

    let manifest_files = files
        .iter()
        .map(|(path, bytes)| {
            Ok(ConfigBundleFile {
                path: normalized_relative_path(path)?,
                sha256: sha256_uri(bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let primary_path = match lane {
        ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation => {
            "config/relay.yaml"
        }
        _ => panic!(),
    };
    let config_hash = manifest_files
        .iter()
        .find(|file| file.path == primary_path)
        .map(|file| file.sha256.clone())
        .ok_or_else(|| anyhow!("development lane lacks its primary product config"))?;
    let bundle_id = development_lane_closure_digest(&manifest_files);
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format development bundle creation time")?;
    let manifest = ConfigBundleManifest {
        schema: "registry.platform.config_bundle.v1".to_string(),
        acceptance_identity: identity,
        bundle_id,
        sequence: 1,
        previous_config_hash: None,
        config_hash: config_hash.clone(),
        files: manifest_files,
        created_at,
    };
    manifest
        .validate()
        .context("development config bundle manifest is invalid")?;
    let canonical_manifest = canonicalize_json(&serde_json::to_value(&manifest)?)
        .context("failed to canonicalize development manifest")?;
    let signature = credentials.with_lane_private_jwk(lane, |private_jwk| {
        let private =
            PrivateJwk::parse(private_jwk).context("development lane private JWK is invalid")?;
        if private
            .public()
            .jkt()
            .context("failed to identify development lane private JWK")?
            != signer_kid
        {
            bail!("development lane private key does not match its projected public signer");
        }
        let algorithm = private
            .algorithm()
            .context("development lane private JWK is invalid")?;
        let signature = sign_payload(&canonical_manifest, &private)
            .context("failed to sign development config bundle")?;
        Ok(ConfigBundleSignature {
            kid: signer_kid.clone(),
            alg: algorithm.jwa_name().to_string(),
            sig: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        })
    })?;
    let envelope = ConfigBundleSignatureEnvelope {
        schema: "registry.platform.config_bundle_signatures.v1".to_string(),
        signatures: vec![signature],
    };
    let lane_root = output_root.join(development_lane_name(lane));
    let bundle_root = lane_root.join("bundle");
    create_dir_owner_only(&bundle_root)?;
    write_file_map(&bundle_root, files)?;
    let manifest_value =
        serde_json::to_value(&manifest).context("failed to serialize development manifest")?;
    write_private_file(
        &bundle_root.join("manifest.json"),
        &canonical_json_line(&manifest_value)?,
    )?;
    let envelope_value =
        serde_json::to_value(&envelope).context("failed to serialize development signatures")?;
    write_private_file(
        &bundle_root.join("manifest.sig.json"),
        &canonical_json_line(&envelope_value)?,
    )?;
    let anchor_path = lane_root.join("anchor.json");
    let anchor_bytes = registry_platform_config::canonical_trust_anchor(&anchor)
        .context("failed to canonicalize development trust anchor")?;
    write_private_file(&anchor_path, &anchor_bytes)?;
    let verified = registry_platform_config::verify_config_bundle(&bundle_root, &anchor_path)
        .context("generated development bundle failed self-verification")?;
    if verified.manifest.config_hash != config_hash
        || verified.manifest.acceptance_identity.trust_domain != ProductTrustDomainV1::Development
    {
        bail!("generated development bundle self-verification changed its binding");
    }
    Ok((bundle_root, anchor_path, config_hash))
}

fn development_lane_closure_digest(files: &[ConfigBundleFile]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.as_bytes());
        hasher.update([0]);
        hasher.update(file.sha256.as_bytes());
        hasher.update([b'\n']);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

const fn development_lane_name(lane: ProductAcceptanceLaneV1) -> &'static str {
    match lane {
        ProductAcceptanceLaneV1::RelayPublic => "relay-public",
        ProductAcceptanceLaneV1::RelayConsultation => "relay-consultation",
        _ => panic!(),
    }
}
