// SPDX-License-Identifier: Apache-2.0
//! Closed local-development runtime planning and lifecycle orchestration.
//!
//! The authoring compiler owns conversion from project documents into
//! [`DevRuntimePlanInput`]. This module deliberately does not parse authoring
//! YAML or infer defaults. It validates the closed projection, binds every
//! lifecycle operation to one project instance, and keeps disposable
//! credentials outside reports and process arguments.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use registry_platform_config::{
    verify_config_bundle, ProductAcceptanceIdentityV1, ProductAcceptanceLaneV1,
    ProductAcceptanceProductV1, ProductTrustDomainV1, MAX_MANIFEST_BYTES,
};
use registry_platform_crypto::canonicalize_json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::dev_credentials::{
    DevCredentialPublicProjection, DevOAuthCredentialProfile, DevSourceCredentialProjection,
    PreparedDevActionCredentialFile, PreparedDevCredentialClosure, PreparedDevCredentialFiles,
    PreparedDevSourceCredentialFiles,
};
use crate::project_authoring::{
    build_registry_project, compile_and_sign_dev_lanes, compile_dev_runtime_authoring,
    AuthoredRecordsRequest, ProjectBuildOptions,
};
use crate::release_lock::{
    verify_installed_release_lock, LockedMountSourceV1, LockedOperatorFileV1,
    LockedRuntimeActionV1, LockedSecretProjectionV1, LockedServiceHardeningV1,
    VerifiedReleaseLockV1,
};

pub const DEV_RUNTIME_STATE_SCHEMA_V1: &str = "registryctl.dev_runtime_state.v1";
pub const DEV_STATUS_REPORT_SCHEMA_V1: &str = "registryctl.dev_status.v1";
pub const DEV_LOGS_REPORT_SCHEMA_V1: &str = "registryctl.dev_logs.v1";
pub const DEV_SMOKE_REPORT_SCHEMA_V1: &str = "registryctl.dev_smoke.v1";
pub const DEV_SYNTHETIC_SOURCE_ORIGIN: &str = "https://10.89.0.3:8099";
const DEV_PRIVATE_SUBNET: &str = "10.89.0.0/24";
const DEV_SYNTHETIC_SOURCE_CA_CONTAINER_PATH: &str =
    "/run/registry/dev-public/synthetic-source-tls.crt";

const DEV_ROOT: &str = ".registry-stack/dev";
const RUNTIME_STATE_FILE: &str = "runtime-state.json";
const RECORDS_REQUEST_CONFIG_FILE: &str = "records-request.curl";
const RECORDS_DENIED_CONFIG_FILE: &str = "records-denied.curl";
const SYNTHETIC_SOURCE_PLAN_FILE: &str = "synthetic-source-plan.json";
const SYNTHETIC_SOURCE_PLAN_SCHEMA_V1: &str = "registry.relay.synthetic-source-plan.v1";
const SYNTHETIC_SOURCE_PLAN_CONTAINER_PATH: &str = "/run/registry/synthetic-source-plan.json";
const SYNTHETIC_SOURCE_SECRET_ROOT: &str = "/run/registry/synthetic-source-secrets";
const MAX_RUNTIME_STATE_BYTES: u64 = 256 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_SYNTHETIC_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_COMPOSE_BYTES: u64 = 1024 * 1024;
const MAX_RUNTIME_PLAN_BYTES: u64 = 2 * 1024 * 1024;
// The generated local Relay uses its closed 256 MiB XLSX/source-file ceiling.
// Keep planning and pre-start verification at that same maximum so Registryctl
// never accepts a workbook that the released Relay cannot read.
pub(crate) const MAX_LOCAL_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ID_BYTES: usize = 128;
const DEFAULT_RELAY_PORT: u16 = 4242;
const DEFAULT_SHUTDOWN_SECONDS: u16 = 15;
const MAX_LOG_LINES_PER_PRODUCT: u16 = 500;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevEnvironmentProfile {
    Local,
    HostedLab,
    Production,
    EvidenceGrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevSourceMode {
    Synthetic,
    LocalSnapshot,
    OperatorBound,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevSourceProvider {
    Http,
    Spreadsheet,
    Rhai,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevOAuthProfile {
    None,
    Oauth2Bearer,
    Oauth2BearerNoExpiry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticRequestEncoding {
    Json,
    Form,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthoredDevScenario {
    pub integration_id: String,
    pub fixture_id: String,
    pub synthetic: bool,
    pub source_provider: DevSourceProvider,
    pub request_encoding: SyntheticRequestEncoding,
    pub oauth_profile: DevOAuthProfile,
    pub denial_scenario_id: String,
    pub authorized_scenario_id: String,
    pub minimized_claim_ids: Vec<String>,
    /// Binds the request-selected claim values and disclosure semantics without
    /// persisting those values in the generated runtime plan.
    pub expected_claim_results_sha256: String,
    pub synthetic_source: Option<AuthoredSyntheticSourcePlan>,
    /// The compiler-produced governed request. It is intentionally private to
    /// the owner-only request materializer and is never serialized or logged.
    pub request_json: Vec<u8>,
}

impl fmt::Debug for AuthoredDevScenario {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoredDevScenario")
            .field("integration_id", &self.integration_id)
            .field("fixture_id", &self.fixture_id)
            .field("synthetic", &self.synthetic)
            .field("source_provider", &self.source_provider)
            .field("request_encoding", &self.request_encoding)
            .field("oauth_profile", &self.oauth_profile)
            .field("denial_scenario_id", &self.denial_scenario_id)
            .field("authorized_scenario_id", &self.authorized_scenario_id)
            .field("minimized_claim_ids", &self.minimized_claim_ids)
            .field(
                "expected_claim_results_sha256",
                &self.expected_claim_results_sha256,
            )
            .field(
                "synthetic_source",
                &self.synthetic_source.as_ref().map(|_| "<redacted>"),
            )
            .field("request_json", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticSourceScenario {
    AuthoredResponse,
    NoMatch,
    Ambiguity,
    SubjectMismatch,
    SourceRejected,
    SourceMalformed,
    SourceTimeout,
    SourceOversize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticOAuthResponseCase {
    Valid,
    MissingAccessToken,
    WrongTokenType,
    MissingExpiresIn,
    UnexpectedExpiresIn,
    DuplicateAccessToken,
    UnknownField,
    RefreshToken,
    IdToken,
    Redirect,
    Rejected,
    UnexpectedContentType,
    Oversize,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthoredSyntheticSourcePlan {
    pub scenario: SyntheticSourceScenario,
    pub source_request: AuthoredSyntheticSourceRequest,
    pub source_auth: Option<SyntheticSourceAuth>,
    pub oauth_response_case: Option<SyntheticOAuthResponseCase>,
    pub oauth_request: Option<AuthoredSyntheticOauthRequest>,
    pub response_body: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticRequestMethod {
    Get,
    Post,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthoredSyntheticSourceRequest {
    pub method: SyntheticRequestMethod,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<serde_json::Value>,
}

impl fmt::Debug for AuthoredSyntheticSourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoredSyntheticSourceRequest")
            .field("method", &self.method)
            .field("path", &"<redacted>")
            .field("query", &"<redacted>")
            .field("headers", &"<redacted>")
            .field("body", &self.body.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyntheticSourceAuth {
    StaticBearer,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthoredSyntheticOauthRequest {
    pub audience: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
}

impl fmt::Debug for AuthoredSyntheticOauthRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoredSyntheticOauthRequest")
            .field("audience", &self.audience.as_ref().map(|_| "<redacted>"))
            .field("scope", &self.scope.as_ref().map(|_| "<redacted>"))
            .field("resource", &self.resource.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Debug for AuthoredSyntheticSourcePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthoredSyntheticSourcePlan")
            .field("scenario", &self.scenario)
            .field("source_request", &"<redacted>")
            .field("source_auth", &self.source_auth)
            .field("oauth_response_case", &self.oauth_response_case)
            .field(
                "oauth_request",
                &self.oauth_request.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "response_body",
                &self.response_body.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl fmt::Debug for DevRuntimePlanInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevRuntimePlanInput")
            .field("project_root", &self.project_root)
            .field("project_id", &self.project_id)
            .field("environment_id", &self.environment_id)
            .field("environment_profile", &self.environment_profile)
            .field("build_manifest", &self.build_manifest)
            .field("release", &self.release)
            .field("development", &self.development)
            .field("scenario_count", &self.scenarios.len())
            .field(
                "local_snapshot",
                &self.local_snapshot.as_ref().map(|_| "<redacted>"),
            )
            .field("artifacts", &self.artifacts)
            .field("credentials", &"<redacted>")
            .field(
                "operator_source_secret_env",
                &self.operator_source_secret_env,
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoredDevelopment {
    pub source_mode: DevSourceMode,
    pub default_integration: String,
    pub default_fixture: String,
    /// Must be true only when the authoring compiler verified an explicit
    /// operator-owned source binding. No locator or secret value enters this
    /// projection.
    pub operator_source_binding_present: bool,
    pub relay_port: Option<u16>,
}

/// One validated project-owned snapshot exposed read-only to Relay serve
/// workloads. This projection deliberately does not implement `Debug` or
/// `Serialize`, so authored workstation paths cannot enter user reports.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct AuthoredLocalSnapshot {
    pub(crate) host_path: PathBuf,
    pub(crate) container_path: String,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevBuildManifestBinding {
    pub path: PathBuf,
    pub digest: String,
    pub project: String,
    pub environment: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevRuntimeArtifactInputs {
    pub compose_file: PathBuf,
    pub relay_public_bundle: PathBuf,
    pub relay_public_anchor: PathBuf,
    pub relay_consultation_bundle: PathBuf,
    pub relay_consultation_anchor: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct VerifiedDevReleaseProjection {
    release_id: String,
    release_tag: String,
    registry_relay_image: String,
    postgresql_image: String,
    minimum_compose_version: String,
    relay_public_prepare: DevRuntimeActionProjection,
    relay_public_initialize: DevRuntimeActionProjection,
    relay_public_serve: DevRuntimeActionProjection,
    relay_consultation_prepare: DevRuntimeActionProjection,
    relay_consultation_initialize: DevRuntimeActionProjection,
    relay_consultation_serve: DevRuntimeActionProjection,
    postgresql_serve: DevRuntimeActionProjection,
    postgresql_bootstrap: DevRuntimeActionProjection,
    postgresql_server_environment: Vec<String>,
    postgresql_hardening: DevWorkloadHardening,
    postgresql_operator_files: Vec<DevOperatorFileProjection>,
    relay_public_health_probe: Vec<String>,
    relay_consultation_health_probe: Vec<String>,
    postgresql_health_probe: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevRuntimeActionProjection {
    command: Vec<String>,
    mounts: Vec<DevRuntimeMountProjection>,
    environment_files: Vec<String>,
    secret_files: Vec<DevSecretProjection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DevRuntimeMountProjection {
    Bundle,
    Anchor,
    AntiRollbackState,
    Audit,
    PostgresqlData,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevSecretProjection {
    file_id: String,
    target: String,
    mode: String,
    uid: String,
    gid: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DevOperatorFileProjection {
    id: String,
    mode: String,
    allowed_owners: Vec<String>,
    required_keys: Vec<String>,
}

impl From<&LockedRuntimeActionV1> for DevRuntimeActionProjection {
    fn from(action: &LockedRuntimeActionV1) -> Self {
        Self {
            command: action.command.clone(),
            mounts: action
                .mounts
                .iter()
                .map(|mount| match mount.source {
                    LockedMountSourceV1::Bundle => DevRuntimeMountProjection::Bundle,
                    LockedMountSourceV1::Anchor => DevRuntimeMountProjection::Anchor,
                    LockedMountSourceV1::AntiRollbackState => {
                        DevRuntimeMountProjection::AntiRollbackState
                    }
                    LockedMountSourceV1::Audit => DevRuntimeMountProjection::Audit,
                    LockedMountSourceV1::PostgresqlData => {
                        DevRuntimeMountProjection::PostgresqlData
                    }
                })
                .collect(),
            environment_files: action.environment_files.clone(),
            secret_files: action.secret_files.iter().map(Into::into).collect(),
        }
    }
}

impl From<&LockedSecretProjectionV1> for DevSecretProjection {
    fn from(projection: &LockedSecretProjectionV1) -> Self {
        Self {
            file_id: projection.file_id.clone(),
            target: projection.target.clone(),
            mode: projection.mode.clone(),
            uid: projection.uid.clone(),
            gid: projection.gid.clone(),
        }
    }
}

impl From<&LockedOperatorFileV1> for DevOperatorFileProjection {
    fn from(projection: &LockedOperatorFileV1) -> Self {
        Self {
            id: projection.id.clone(),
            mode: projection.mode.clone(),
            allowed_owners: projection.allowed_owners.clone(),
            required_keys: projection.required_keys.clone(),
        }
    }
}

impl From<&LockedServiceHardeningV1> for DevWorkloadHardening {
    fn from(hardening: &LockedServiceHardeningV1) -> Self {
        Self {
            user: hardening.user.clone(),
            read_only_root_filesystem: hardening.read_only_root_filesystem,
            cap_drop: hardening.cap_drop.clone(),
            cap_add: Vec::new(),
            security_opt: hardening.security_opt.clone(),
            tmpfs: hardening.tmpfs.clone(),
        }
    }
}

impl VerifiedDevReleaseProjection {
    /// Projects the already verified release authority into the dev runtime.
    ///
    /// This is crate-visible so the release-lock verifier remains the only
    /// component that can establish authenticity. It copies only values from
    /// the non-constructible verified capability.
    pub(crate) fn from_verified_release_lock(lock: &VerifiedReleaseLockV1) -> Self {
        let images = lock.managed_images();
        let runtime = lock.runtime_mapping();
        Self {
            release_id: lock.signed_payload_sha256().to_string(),
            release_tag: lock.release_tag().to_string(),
            registry_relay_image: images.relay().to_string(),
            postgresql_image: images.postgresql_state_plane().to_string(),
            minimum_compose_version: lock.minimum_compose_version().to_string(),
            relay_public_prepare: runtime
                .relay_public()
                .development_prepare_state_store_action()
                .into(),
            relay_public_initialize: runtime
                .relay_public()
                .development_initialize_state_action()
                .into(),
            relay_public_serve: runtime.relay_public().development_serve_action().into(),
            relay_consultation_prepare: runtime
                .relay_consultation()
                .development_prepare_state_store_action()
                .into(),
            relay_consultation_initialize: runtime
                .relay_consultation()
                .development_initialize_state_action()
                .into(),
            relay_consultation_serve: runtime
                .relay_consultation()
                .development_serve_action()
                .into(),
            postgresql_serve: runtime.postgresql_state_plane().serve().into(),
            postgresql_bootstrap: runtime.postgresql_state_plane().bootstrap().into(),
            postgresql_server_environment: runtime
                .postgresql_state_plane()
                .server_environment()
                .to_vec(),
            postgresql_hardening: runtime.postgresql_state_plane().hardening().into(),
            postgresql_operator_files: runtime
                .operator_files()
                .iter()
                .filter(|file| {
                    file.id == "postgresql-admin-password"
                        || file.id == "postgresql-tls-certificate"
                        || file.id == "postgresql-tls-private-key"
                        || file.id == "postgresql-bootstrap-environment"
                })
                .map(Into::into)
                .collect(),
            relay_public_health_probe: runtime.relay_public().health_probe().to_vec(),
            relay_consultation_health_probe: runtime.relay_consultation().health_probe().to_vec(),
            postgresql_health_probe: runtime.postgresql_state_plane().health_probe().to_vec(),
        }
    }

    #[cfg(test)]
    #[cfg_attr(
        test,
        allow(dead_code, reason = "used by direct-module integration tests")
    )]
    pub(crate) fn test_only(
        release_id: String,
        release_tag: String,
        registry_relay_image: String,
        postgresql_image: String,
        minimum_compose_version: String,
    ) -> DevRuntimeResult<Self> {
        if release_id.is_empty()
            || release_id.len() > 256
            || !valid_release_tag(&release_tag)
            || parse_version(&minimum_compose_version).is_none()
        {
            return Err(DevRuntimeError::image_lock());
        }
        validate_image_ref(
            &registry_relay_image,
            "ghcr.io/registrystack/registry-relay",
        )?;
        validate_image_ref(&postgresql_image, "docker.io/library/postgres")?;
        Ok(Self {
            release_id,
            release_tag,
            registry_relay_image,
            postgresql_image,
            minimum_compose_version,
            relay_public_prepare: relay_development_action("relay-public", "prepare_state_store"),
            relay_public_initialize: relay_development_action("relay-public", "initialize_state"),
            relay_public_serve: relay_development_action("relay-public", "serve"),
            relay_consultation_prepare: relay_development_action(
                "relay-consultation",
                "prepare_state_store",
            ),
            relay_consultation_initialize: relay_development_action(
                "relay-consultation",
                "initialize_state",
            ),
            relay_consultation_serve: relay_development_action("relay-consultation", "serve"),
            postgresql_serve: DevRuntimeActionProjection {
                command: vec![
                    "postgres".into(),
                    "-c".into(),
                    "ssl=on".into(),
                    "-c".into(),
                    "ssl_cert_file=/run/secrets/postgresql-tls-certificate".into(),
                    "-c".into(),
                    "ssl_key_file=/run/secrets/postgresql-tls-private-key".into(),
                ],
                mounts: vec![DevRuntimeMountProjection::PostgresqlData],
                environment_files: Vec::new(),
                secret_files: vec![
                    test_postgresql_secret(
                        "postgresql-admin-password",
                        "/run/secrets/postgresql-admin-password",
                    ),
                    test_postgresql_secret(
                        "postgresql-tls-certificate",
                        "/run/secrets/postgresql-tls-certificate",
                    ),
                    test_postgresql_secret(
                        "postgresql-tls-private-key",
                        "/run/secrets/postgresql-tls-private-key",
                    ),
                ],
            },
            postgresql_bootstrap: DevRuntimeActionProjection {
                command: vec![
                    "/bin/bash".into(),
                    "-ceu".into(),
                    "psql \"sslmode=verify-full host=registry-postgres\"".into(),
                ],
                mounts: Vec::new(),
                environment_files: vec!["postgresql-bootstrap-environment".into()],
                secret_files: vec![
                    test_postgresql_secret(
                        "postgresql-admin-password",
                        "/run/secrets/postgresql-admin-password",
                    ),
                    test_postgresql_secret(
                        "postgresql-tls-certificate",
                        "/run/secrets/postgresql-tls-certificate",
                    ),
                ],
            },
            postgresql_server_environment: vec![
                "POSTGRES_USER=registry_stack_bootstrap".into(),
                "POSTGRES_DB=postgres".into(),
                "POSTGRES_PASSWORD_FILE=/run/secrets/postgresql-admin-password".into(),
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=peer".into(),
            ],
            postgresql_hardening: DevWorkloadHardening {
                user: "999:999".into(),
                read_only_root_filesystem: true,
                cap_drop: vec!["ALL".into()],
                cap_add: Vec::new(),
                security_opt: vec!["no-new-privileges:true".into()],
                tmpfs: vec!["/tmp".into(), "/var/run/postgresql".into()],
            },
            postgresql_operator_files: vec![
                test_postgresql_operator_file("postgresql-admin-password", &[]),
                test_postgresql_operator_file("postgresql-tls-certificate", &[]),
                test_postgresql_operator_file("postgresql-tls-private-key", &[]),
                test_postgresql_operator_file(
                    "postgresql-bootstrap-environment",
                    &[
                        "REGISTRY_RELAY_MIGRATOR_PASSWORD",
                        "REGISTRY_RELAY_RUNTIME_PASSWORD",
                        "REGISTRY_RELAY_MAINTENANCE_PASSWORD",
                        "REGISTRY_RELAY_READER_PASSWORD",
                    ],
                ),
            ],
            relay_public_health_probe: vec!["registry-relay".into(), "health".into()],
            relay_consultation_health_probe: vec!["registry-relay".into(), "health".into()],
            postgresql_health_probe: vec!["pg_isready".into()],
        })
    }
}

/// Prepare the complete closed local-development runtime from authored project
/// inputs. Callers cannot inject credentials, images, commands, or trust
/// material through this boundary.
pub fn prepare_dev_runtime_plan(
    project_directory: &Path,
    environment_id: &str,
) -> DevRuntimeResult<DevRuntimePlan> {
    let canonical_root = fs::canonicalize(project_directory).map_err(|_| {
        DevRuntimeError::new(
            DevFailureCategory::ProjectBinding,
            "project root cannot be resolved safely",
            "select an existing Registry Stack project directory",
        )
    })?;
    let authoring =
        compile_dev_runtime_authoring(&canonical_root, environment_id).map_err(|error| {
            DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                error.to_string(),
                "correct the authored development environment and retry",
            )
        })?;
    let binding = DevProjectBindingV1 {
        project: authoring.project_id.clone(),
        environment: authoring.environment_id.clone(),
        project_root_digest: sha256_uri(canonical_root.to_string_lossy().as_bytes()),
    };
    let runtime_id = stable_runtime_id(&binding)?;
    let mut generation_bytes = [0_u8; 8];
    getrandom::fill(&mut generation_bytes).map_err(|_| DevRuntimeError::io())?;
    let generation = hex::encode(generation_bytes);
    let generated_root = canonical_root
        .join(".registry-stack/dev-artifacts")
        .join(environment_id)
        .join(&runtime_id)
        .join(generation);
    validate_runtime_ancestors(
        &canonical_root,
        generated_root.parent().ok_or_else(DevRuntimeError::io)?,
    )?;
    let mut generated_guard =
        CandidateArtifactGuard::from_roots(canonical_root.clone(), generated_root.clone())?;

    let report = build_registry_project(&ProjectBuildOptions {
        project_directory: canonical_root.clone(),
        environment: environment_id.to_string(),
        against: None,
        anchor: None,
    })
    .map_err(|error| {
        DevRuntimeError::new(
            DevFailureCategory::StaleBuild,
            error.to_string(),
            "correct failing project checks and retry registryctl dev",
        )
    })?;
    let manifest = report.artifact_manifest.ok_or_else(|| {
        DevRuntimeError::new(
            DevFailureCategory::StaleBuild,
            "project build did not produce its required artifact manifest",
            "rerun registryctl check and retry registryctl dev",
        )
    })?;
    let build_manifest = DevBuildManifestBinding {
        path: canonical_root.join(manifest.path.as_str()),
        digest: manifest.digest.as_str().to_string(),
        project: authoring.project_id.clone(),
        environment: environment_id.to_string(),
    };

    // Credentials are generated before the compiler sees any disposable
    // binding. The compiler receives only their nonsecret public projection
    // and signs both Relay lanes before Compose is rendered.
    let credentials = PreparedDevCredentialClosure::generate(authoring.credential_requirements())
        .map_err(|_| DevRuntimeError::invalid_credentials())?;
    let signed_root = generated_root.join("signed-lanes");
    let signed =
        compile_and_sign_dev_lanes(&canonical_root, environment_id, &credentials, &signed_root)
            .map_err(|error| {
                let _ = remove_generated_dev_artifact(&canonical_root, &generated_root);
                DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    error.to_string(),
                    "correct the authored environment and rebuild its disposable development lanes",
                )
            })?;

    let executable = std::env::current_exe().map_err(|_| DevRuntimeError::image_lock())?;
    let installed_lock = executable
        .parent()
        .ok_or_else(DevRuntimeError::image_lock)?
        .join("registry-release-lock.v1.json");
    let verified_lock = verify_installed_release_lock(&installed_lock)
        .map_err(|_| DevRuntimeError::image_lock())?;
    let release = VerifiedDevReleaseProjection::from_verified_release_lock(&verified_lock);
    let compose_file = generated_root.join("compose.json");
    let artifacts = DevRuntimeArtifactInputs {
        compose_file: compose_file.clone(),
        relay_public_bundle: signed.relay_public_bundle,
        relay_public_anchor: signed.relay_public_anchor,
        relay_consultation_bundle: signed.relay_consultation_bundle,
        relay_consultation_anchor: signed.relay_consultation_anchor,
    };

    let paths = runtime_paths(&canonical_root, environment_id, &runtime_id);
    let credential_files = credentials.planned_files(&paths.credentials);
    let workloads = build_workloads(
        &authoring.project_id,
        environment_id,
        &release,
        &artifacts,
        &paths,
        &credential_files,
        DevWorkloadBuildOptions {
            relay_port: authoring
                .development
                .relay_port
                .unwrap_or(DEFAULT_RELAY_PORT),
            synthetic: authoring.development.source_mode == DevSourceMode::Synthetic,
            local_snapshot: authoring.local_snapshot.as_ref(),
            operator_source_secret_env: &authoring.operator_source_secret_env,
        },
    )
    .inspect_err(|_| {
        let _ = remove_generated_dev_artifact(&canonical_root, &generated_root);
    })?;
    if let Err(error) =
        render_closed_compose(&compose_file, &workloads, authoring.development.source_mode)
    {
        let _ = remove_generated_dev_artifact(&canonical_root, &generated_root);
        return Err(error);
    }

    let plan = DevRuntimePlan::derive(DevRuntimePlanInput {
        project_root: canonical_root,
        project_id: authoring.project_id,
        environment_id: authoring.environment_id,
        environment_profile: authoring.environment_profile,
        build_manifest,
        release,
        development: authoring.development,
        scenarios: authoring.scenarios,
        records_request: authoring.records_request,
        local_snapshot: authoring.local_snapshot,
        artifacts,
        credentials,
        operator_source_secret_env: authoring.operator_source_secret_env,
    })?;
    generated_guard.disarm();
    Ok(plan)
}

/// Load the exact value-free plan bound to an existing disposable runtime.
/// This path does not generate credentials, rebuild authoring, sign lanes, or
/// mutate any project/runtime file.
pub fn load_bound_dev_runtime_plan(
    project_directory: &Path,
    environment_id: &str,
) -> DevRuntimeResult<DevRuntimePlan> {
    validate_id("environment", environment_id)?;
    let canonical_root =
        fs::canonicalize(project_directory).map_err(|_| DevRuntimeError::project_binding())?;
    let environment_root = canonical_root.join(DEV_ROOT).join(environment_id);
    let entries =
        fs::read_dir(&environment_root).map_err(|_| DevRuntimeError::project_binding())?;
    let mut runtime_roots = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| DevRuntimeError::project_binding())?;
        let metadata = entry
            .metadata()
            .map_err(|_| DevRuntimeError::project_binding())?;
        if metadata.is_dir() && !entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
            runtime_roots.push(entry.path());
        }
    }
    if runtime_roots.len() != 1 {
        return Err(DevRuntimeError::new(
            DevFailureCategory::AmbiguousRuntime,
            "development runtime binding is missing or ambiguous",
            "select the exact project and environment that owns one runtime",
        ));
    }
    let plan_file = runtime_roots[0].join("runtime-plan.json");
    let bytes = read_owner_only_regular_file(&plan_file, MAX_RUNTIME_PLAN_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    let plan: DevRuntimePlan =
        parse_json_strict(&bytes).map_err(|_| DevRuntimeError::project_binding())?;
    let expected_digest = sha256_uri(canonical_root.to_string_lossy().as_bytes());
    if plan.binding.environment != environment_id
        || plan.binding.project_root_digest != expected_digest
        || plan.paths.root != runtime_roots[0]
        || plan.paths.plan_file != plan_file
        || plan.credentials.is_some()
        || plan.credential_files.is_some()
    {
        return Err(DevRuntimeError::project_binding());
    }
    load_bound_state(&plan)?;
    Ok(plan)
}

fn runtime_paths(root: &Path, environment_id: &str, runtime_id: &str) -> DevRuntimePaths {
    let runtime_root = root.join(DEV_ROOT).join(environment_id).join(runtime_id);
    DevRuntimePaths {
        state_file: runtime_root.join(RUNTIME_STATE_FILE),
        plan_file: runtime_root.join("runtime-plan.json"),
        credentials: runtime_root.join("credentials"),
        records_request_config: runtime_root
            .join("credentials")
            .join(RECORDS_REQUEST_CONFIG_FILE),
        records_denied_config: runtime_root
            .join("credentials")
            .join(RECORDS_DENIED_CONFIG_FILE),
        synthetic_source_plan: runtime_root.join(SYNTHETIC_SOURCE_PLAN_FILE),
        postgresql_staged_files: runtime_root.join("postgresql-staged-files"),
        root: runtime_root,
    }
}

fn remove_generated_dev_artifact(root: &Path, target: &Path) -> DevRuntimeResult<()> {
    if !target.exists() {
        return Ok(());
    }
    let parent = target.parent().ok_or_else(DevRuntimeError::io)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|_| DevRuntimeError::io())?;
    if !valid_generated_artifact_root(root, target) || !canonical_parent.starts_with(root) {
        return Err(DevRuntimeError::project_binding());
    }
    let metadata = fs::symlink_metadata(target).map_err(|_| DevRuntimeError::io())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DevRuntimeError::project_binding());
    }
    fs::remove_dir_all(target).map_err(|_| DevRuntimeError::io())
}

fn valid_generated_artifact_root(project_root: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(project_root.join(".registry-stack/dev-artifacts"))
    else {
        return false;
    };
    let components = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    components.len() == 3
        && validate_id("environment", components[0]).is_ok()
        && components[1].len() == 16
        && components[2].len() == 16
        && components[1..].iter().all(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

pub(crate) struct DevRuntimePlanInput {
    pub project_root: PathBuf,
    pub project_id: String,
    pub environment_id: String,
    pub environment_profile: DevEnvironmentProfile,
    pub build_manifest: DevBuildManifestBinding,
    pub release: VerifiedDevReleaseProjection,
    pub development: AuthoredDevelopment,
    pub scenarios: Vec<AuthoredDevScenario>,
    pub records_request: Option<AuthoredRecordsRequest>,
    pub local_snapshot: Option<AuthoredLocalSnapshot>,
    pub artifacts: DevRuntimeArtifactInputs,
    pub credentials: PreparedDevCredentialClosure,
    pub operator_source_secret_env: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevProjectBindingV1 {
    pub project: String,
    pub environment: String,
    pub project_root_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevScenarioPlan {
    pub integration_id: String,
    pub fixture_id: String,
    pub source_provider: DevSourceProvider,
    pub request_encoding: SyntheticRequestEncoding,
    pub oauth_profile: DevOAuthProfile,
    pub denial_scenario_id: String,
    pub authorized_scenario_id: String,
    pub minimized_claim_ids: Vec<String>,
    /// Value-free commitment checked against the authorized smoke response.
    pub expected_claim_results_sha256: String,
    pub synthetic_source_origin: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DevClaimResultExpectation {
    pub claim_id: String,
    pub value: serde_json::Value,
    pub satisfied: Option<bool>,
    pub disclosure: String,
}

pub(crate) fn dev_claim_results_commitment(
    mut results: Vec<DevClaimResultExpectation>,
) -> Result<String, ()> {
    results.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    if results.is_empty()
        || results
            .windows(2)
            .any(|pair| pair[0].claim_id == pair[1].claim_id)
    {
        return Err(());
    }
    let canonical = canonicalize_json(&serde_json::json!({
        "schema": "registryctl.dev_claim_results_commitment.v1",
        "results": results,
    }))
    .map_err(|_| ())?;
    Ok(sha256_uri(&canonical))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DevWorkloadId {
    RelayPublic,
    RelayConsultation,
    Postgresql,
    SyntheticSource,
}

impl DevWorkloadId {
    pub const fn compose_service(self) -> &'static str {
        match self {
            Self::RelayPublic => "registry-relay-public",
            Self::RelayConsultation => "registry-relay-consultation",
            Self::Postgresql => "registry-postgres",
            Self::SyntheticSource => "registry-synthetic-source",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevWorkloadPlan {
    pub id: DevWorkloadId,
    pub image: String,
    pub acceptance_identity: Option<ProductAcceptanceIdentityV1>,
    pub host_endpoint: Option<SocketAddr>,
    pub prepare_state_store: Option<DevProductActionPlan>,
    pub initialize_state: Option<DevProductActionPlan>,
    pub command: Vec<String>,
    pub health_probe: Vec<String>,
    pub environment_passthrough: Vec<String>,
    pub mounts: Vec<DevWorkloadMount>,
    pub hardening: Option<DevWorkloadHardening>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevProductActionPlan {
    pub compose_service: String,
    pub command: Vec<String>,
    pub mounts: Vec<DevWorkloadMount>,
    pub private_network: bool,
    pub hardening: Option<DevWorkloadHardening>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevWorkloadHardening {
    pub user: String,
    pub read_only_root_filesystem: bool,
    pub cap_drop: Vec<String>,
    pub cap_add: Vec<String>,
    pub security_opt: Vec<String>,
    pub tmpfs: Vec<String>,
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevWorkloadMount {
    pub host_path: PathBuf,
    pub container_path: String,
    pub read_only: bool,
    pub kind: DevWorkloadMountKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevWorkloadMountKind {
    Bind,
    ProjectFile,
    Secret,
}

impl fmt::Debug for DevWorkloadMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevWorkloadMount")
            .field("host_path", &"<redacted>")
            .field("container_path", &self.container_path)
            .field("read_only", &self.read_only)
            .field("kind", &self.kind)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevLifecycleBindings {
    pub compose_project: String,
    pub compose_file: PathBuf,
    pub status_services: Vec<DevWorkloadId>,
    pub log_services: Vec<DevWorkloadId>,
    pub smoke_denial_scenario: String,
    pub smoke_authorized_scenario: String,
    pub shutdown_timeout_seconds: u16,
    pub max_log_lines_per_product: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevRuntimePaths {
    pub root: PathBuf,
    pub state_file: PathBuf,
    pub plan_file: PathBuf,
    pub credentials: PathBuf,
    pub records_request_config: PathBuf,
    pub records_denied_config: PathBuf,
    pub synthetic_source_plan: PathBuf,
    pub postgresql_staged_files: PathBuf,
}

#[derive(Deserialize, Serialize)]
pub struct DevRuntimePlan {
    pub binding: DevProjectBindingV1,
    pub plan_digest: String,
    pub build_manifest_digest: String,
    pub release_tag: String,
    pub minimum_compose_version: String,
    pub compose_digest: String,
    pub records_request_digest: Option<String>,
    pub local_snapshot_digest: Option<String>,
    pub source_mode: DevSourceMode,
    pub scenario: DevScenarioPlan,
    pub workloads: Vec<DevWorkloadPlan>,
    pub lifecycle: DevLifecycleBindings,
    pub paths: DevRuntimePaths,
    pub artifacts: DevRuntimeArtifactInputs,
    #[serde(skip)]
    records_request: Option<AuthoredRecordsRequest>,
    #[serde(skip)]
    synthetic_source_plan: Option<SyntheticSourcePlanV1>,
    #[serde(skip)]
    credentials: Option<PreparedDevCredentialClosure>,
    #[serde(skip)]
    credential_files: Option<PreparedDevCredentialFiles>,
}

impl fmt::Debug for DevRuntimePlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevRuntimePlan")
            .field("binding", &self.binding)
            .field("plan_digest", &self.plan_digest)
            .field("build_manifest_digest", &self.build_manifest_digest)
            .field("release_tag", &self.release_tag)
            .field("minimum_compose_version", &self.minimum_compose_version)
            .field("compose_digest", &self.compose_digest)
            .field("records_request_digest", &self.records_request_digest)
            .field("local_snapshot_digest", &self.local_snapshot_digest)
            .field("source_mode", &self.source_mode)
            .field("scenario", &self.scenario)
            .field("workloads", &self.workloads)
            .field("lifecycle", &self.lifecycle)
            .field("paths", &self.paths)
            .field("artifacts", &self.artifacts)
            .field(
                "records_request",
                &self.records_request.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "synthetic_source_plan",
                &self.synthetic_source_plan.as_ref().map(|_| "<redacted>"),
            )
            .field("credentials", &"<redacted>")
            .field("credential_files", &self.credential_files)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSourcePlanV1 {
    version: String,
    scenario: SyntheticSourceScenario,
    source_request: SyntheticSourceRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_auth: Option<SyntheticSourceAuthPlan>,
    request_encoding: SyntheticRequestEncoding,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth: Option<SyntheticOauthPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<serde_json::Value>,
    secrets: SyntheticSourceSecrets,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSourceRequest {
    method: SyntheticRequestMethod,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<serde_json::Value>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SyntheticSourceAuthPlan {
    StaticBearer { secret: SyntheticSecretRef },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticOauthPlan {
    response_profile: DevOAuthProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_case: Option<SyntheticOAuthResponseCase>,
    request: SyntheticOauthRequest,
    secrets: SyntheticOauthSecrets,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticOauthRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticOauthSecrets {
    client_id: SyntheticSecretRef,
    client_secret: SyntheticSecretRef,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSourceSecrets {
    control_token: SyntheticSecretRef,
    tls_certificate: SyntheticSecretRef,
    tls_private_key: SyntheticSecretRef,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticSecretRef {
    file: String,
    generation: u64,
}

impl DevRuntimePlan {
    pub(crate) fn derive(input: DevRuntimePlanInput) -> DevRuntimeResult<Self> {
        validate_id("project", &input.project_id)?;
        validate_id("environment", &input.environment_id)?;
        if matches!(
            input.environment_profile,
            DevEnvironmentProfile::Production | DevEnvironmentProfile::EvidenceGrade
        ) {
            return Err(DevRuntimeError::new(
                DevFailureCategory::UnsafeEnvironment,
                "development runtime refuses production or evidence-grade environments",
                "select an authored local development environment",
            ));
        }
        validate_sha256(&input.build_manifest.digest).map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::StaleBuild,
                "development build manifest is invalid",
                "run registryctl check and rebuild the selected environment",
            )
        })?;
        let build_manifest_bytes =
            read_bounded_regular_file(&input.build_manifest.path, MAX_MANIFEST_BYTES).map_err(
                |_| {
                    DevRuntimeError::new(
                        DevFailureCategory::StaleBuild,
                        "development build manifest is missing or unsafe",
                        "run registryctl check and rebuild the selected environment",
                    )
                },
            )?;
        if sha256_uri(&build_manifest_bytes) != input.build_manifest.digest {
            return Err(DevRuntimeError::new(
                DevFailureCategory::StaleBuild,
                "development build manifest digest is stale",
                "rebuild the selected environment before starting development",
            ));
        }
        if input.build_manifest.project != input.project_id
            || input.build_manifest.environment != input.environment_id
        {
            return Err(DevRuntimeError::new(
                DevFailureCategory::StaleBuild,
                "development build manifest is bound to a different project or environment",
                "rebuild the selected environment before starting development",
            ));
        }
        let canonical_root = fs::canonicalize(&input.project_root).map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::ProjectBinding,
                "project root cannot be resolved safely",
                "select an existing project directory and retry",
            )
        })?;
        let metadata = fs::symlink_metadata(&canonical_root).map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::ProjectBinding,
                "project root cannot be inspected safely",
                "select an existing project directory and retry",
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DevRuntimeError::new(
                DevFailureCategory::ProjectBinding,
                "project root must be a real directory",
                "select the real project directory and retry",
            ));
        }
        let canonical_build_manifest =
            fs::canonicalize(&input.build_manifest.path).map_err(|_| DevRuntimeError::io())?;
        if !canonical_build_manifest.starts_with(canonical_root.join(".registry-stack/build")) {
            return Err(DevRuntimeError::new(
                DevFailureCategory::StaleBuild,
                "development build manifest is outside the selected project's generated build",
                "rebuild the selected environment with Registryctl",
            ));
        }
        validate_artifact_inputs(&canonical_root, &input.artifacts)?;
        let compose_digest = sha256_uri(
            &read_bounded_regular_file(&input.artifacts.compose_file, MAX_COMPOSE_BYTES)
                .map_err(|_| DevRuntimeError::io())?,
        );
        validate_source_binding(&input.development)?;
        if (input.development.source_mode == DevSourceMode::LocalSnapshot)
            != input.local_snapshot.is_some()
        {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "local snapshot mode must carry exactly one validated project file",
                "select a contained XLSX project file or choose another source mode",
            ));
        }
        if let Some(snapshot) = &input.local_snapshot {
            validate_authored_local_snapshot(&canonical_root, snapshot)?;
        }
        let scenario = select_authored_scenario(&input.development, &input.scenarios)?;
        let records_request_digest = input.records_request.as_ref().map(|request| {
            sha256_uri(
                &[
                    request.dataset_id.as_bytes(),
                    b"\0",
                    request.entity_id.as_bytes(),
                    b"\0",
                    request.record_id.as_bytes(),
                    b"\0",
                    request.purpose.as_bytes(),
                ]
                .concat(),
            )
        });
        if input.development.source_mode != DevSourceMode::Synthetic
            && scenario.synthetic_source.is_some()
        {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "non-synthetic source mode cannot carry a synthetic source plan",
                "remove the synthetic plan or select synthetic source mode",
            ));
        }
        let relay_port = input.development.relay_port.unwrap_or(DEFAULT_RELAY_PORT);
        if relay_port == 0 {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "development Relay loopback port must be non-zero",
                "author a non-zero development.relay_port value",
            ));
        }

        let project_root_digest = sha256_uri(canonical_root.to_string_lossy().as_bytes());
        let binding = DevProjectBindingV1 {
            project: input.project_id.clone(),
            environment: input.environment_id.clone(),
            project_root_digest,
        };
        let runtime_id = stable_runtime_id(&binding)?;
        let runtime_root = canonical_root
            .join(DEV_ROOT)
            .join(&input.environment_id)
            .join(&runtime_id);
        validate_runtime_ancestors(
            &canonical_root,
            runtime_root.parent().ok_or_else(DevRuntimeError::io)?,
        )?;
        let paths = DevRuntimePaths {
            state_file: runtime_root.join(RUNTIME_STATE_FILE),
            plan_file: runtime_root.join("runtime-plan.json"),
            credentials: runtime_root.join("credentials"),
            records_request_config: runtime_root
                .join("credentials")
                .join(RECORDS_REQUEST_CONFIG_FILE),
            records_denied_config: runtime_root
                .join("credentials")
                .join(RECORDS_DENIED_CONFIG_FILE),
            synthetic_source_plan: runtime_root.join(SYNTHETIC_SOURCE_PLAN_FILE),
            postgresql_staged_files: runtime_root.join("postgresql-staged-files"),
            root: runtime_root,
        };
        let credential_files = input.credentials.planned_files(&paths.credentials);
        let records_credentials_present = credential_files.relay_match_token.is_some()
            && credential_files.relay_no_match_token.is_some();
        if input.records_request.is_some() != records_credentials_present
            || credential_files.relay_match_token.is_some()
                != credential_files.relay_no_match_token.is_some()
        {
            return Err(DevRuntimeError::invalid_credentials());
        }
        validate_credential_projection(
            &input.development,
            scenario,
            input.credentials.public_projection(),
            &credential_files,
        )?;
        validate_operator_secret_env(
            input.development.source_mode,
            &input.operator_source_secret_env,
        )?;
        let scenario_plan = DevScenarioPlan {
            integration_id: scenario.integration_id.clone(),
            fixture_id: scenario.fixture_id.clone(),
            source_provider: scenario.source_provider,
            request_encoding: scenario.request_encoding,
            oauth_profile: scenario.oauth_profile,
            denial_scenario_id: scenario.denial_scenario_id.clone(),
            authorized_scenario_id: scenario.authorized_scenario_id.clone(),
            minimized_claim_ids: scenario.minimized_claim_ids.clone(),
            expected_claim_results_sha256: scenario.expected_claim_results_sha256.clone(),
            synthetic_source_origin: (input.development.source_mode == DevSourceMode::Synthetic)
                .then(|| DEV_SYNTHETIC_SOURCE_ORIGIN.to_string()),
        };
        let workloads = build_workloads(
            &input.project_id,
            &input.environment_id,
            &input.release,
            &input.artifacts,
            &paths,
            &credential_files,
            DevWorkloadBuildOptions {
                relay_port,
                synthetic: input.development.source_mode == DevSourceMode::Synthetic,
                local_snapshot: input.local_snapshot.as_ref(),
                operator_source_secret_env: &input.operator_source_secret_env,
            },
        )?;
        validate_development_trust_material(&input.artifacts, &workloads)?;
        let lifecycle = DevLifecycleBindings {
            compose_project: format!("registryctl-dev-{runtime_id}"),
            compose_file: input.artifacts.compose_file.clone(),
            status_services: workloads.iter().map(|workload| workload.id).collect(),
            log_services: vec![
                DevWorkloadId::RelayPublic,
                DevWorkloadId::RelayConsultation,
                DevWorkloadId::SyntheticSource,
            ]
            .into_iter()
            .filter(|id| workloads.iter().any(|workload| workload.id == *id))
            .collect(),
            smoke_denial_scenario: scenario.denial_scenario_id.clone(),
            smoke_authorized_scenario: scenario.authorized_scenario_id.clone(),
            shutdown_timeout_seconds: DEFAULT_SHUTDOWN_SECONDS,
            max_log_lines_per_product: MAX_LOG_LINES_PER_PRODUCT,
        };
        let artifacts = input.artifacts.clone();
        let local_snapshot_digest = input
            .local_snapshot
            .as_ref()
            .map(|snapshot| snapshot.digest.clone());
        let synthetic_source_plan = match input.development.source_mode {
            DevSourceMode::Synthetic => Some(build_synthetic_source_plan(
                scenario,
                credential_files
                    .source
                    .as_ref()
                    .ok_or_else(DevRuntimeError::invalid_credentials)?,
            )?),
            DevSourceMode::OperatorBound => None,
            DevSourceMode::LocalSnapshot => None,
        };
        let plan_digest = plan_digest(DevPlanDigestInput {
            binding: &binding,
            build_manifest_digest: &input.build_manifest.digest,
            release: &input.release,
            source_mode: input.development.source_mode,
            scenario: &scenario_plan,
            workloads: &workloads,
            lifecycle: &lifecycle,
            artifacts: &artifacts,
            compose_digest: &compose_digest,
            records_request_digest: records_request_digest.as_deref(),
            local_snapshot_digest: local_snapshot_digest.as_deref(),
            synthetic_source_plan: synthetic_source_plan.as_ref(),
        })?;

        Ok(Self {
            binding,
            plan_digest,
            build_manifest_digest: input.build_manifest.digest,
            release_tag: input.release.release_tag,
            minimum_compose_version: input.release.minimum_compose_version,
            compose_digest,
            records_request_digest,
            local_snapshot_digest,
            source_mode: input.development.source_mode,
            scenario: scenario_plan,
            workloads,
            lifecycle,
            paths,
            artifacts,
            records_request: input.records_request,
            synthetic_source_plan,
            credentials: Some(input.credentials),
            credential_files: Some(credential_files),
        })
    }

    pub fn public_endpoints(&self) -> Vec<SocketAddr> {
        self.workloads
            .iter()
            .filter_map(|workload| workload.host_endpoint)
            .collect()
    }

    pub fn public_endpoint_urls(&self) -> Vec<String> {
        self.public_endpoints()
            .into_iter()
            .map(|endpoint| format!("http://{endpoint}"))
            .collect()
    }

    pub fn records_request_command(&self) -> Option<String> {
        self.records_request_digest.as_ref().map(|_| {
            format!(
                "curl --config {}",
                shell_quote_path(&self.paths.records_request_config)
            )
        })
    }

    pub fn records_denied_command(&self) -> Option<String> {
        self.records_request_digest.as_ref().map(|_| {
            format!(
                "curl --config {}",
                shell_quote_path(&self.paths.records_denied_config)
            )
        })
    }

    pub fn logs_command(&self) -> String {
        "registryctl dev logs".to_string()
    }

    pub fn smoke_command(&self) -> String {
        "registryctl dev smoke".to_string()
    }

    pub fn down_command(&self) -> String {
        "registryctl dev down".to_string()
    }

    fn image_refs(&self) -> Vec<&str> {
        let mut refs = BTreeSet::new();
        for workload in &self.workloads {
            refs.insert(workload.image.as_str());
        }
        refs.into_iter().collect()
    }

    fn relay_public_endpoint(&self) -> DevRuntimeResult<SocketAddr> {
        self.workloads
            .iter()
            .find(|workload| workload.id == DevWorkloadId::RelayPublic)
            .and_then(|workload| workload.host_endpoint)
            .ok_or_else(|| {
                DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "development plan has no public Relay endpoint",
                    "rebuild the development runtime plan",
                )
            })
    }

    fn prepared_credential_files(&self) -> DevRuntimeResult<&PreparedDevCredentialFiles> {
        self.credential_files
            .as_ref()
            .ok_or_else(DevRuntimeError::invalid_credentials)
    }
}

fn validate_source_binding(development: &AuthoredDevelopment) -> DevRuntimeResult<()> {
    match development.source_mode {
        DevSourceMode::Synthetic if development.operator_source_binding_present => {
            Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "synthetic development mode cannot carry an operator source binding",
                "remove the real-source binding or select operator_bound mode explicitly",
            ))
        }
        DevSourceMode::OperatorBound if !development.operator_source_binding_present => {
            Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "operator-bound development mode requires an explicit source binding",
                "author the operator-owned source binding and retry",
            ))
        }
        DevSourceMode::LocalSnapshot if development.operator_source_binding_present => {
            Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "local snapshot development cannot carry an operator source binding",
                "remove the remote-source binding and select one contained project file",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_authored_local_snapshot(
    project_root: &Path,
    snapshot: &AuthoredLocalSnapshot,
) -> DevRuntimeResult<()> {
    let canonical =
        fs::canonicalize(&snapshot.host_path).map_err(|_| DevRuntimeError::project_binding())?;
    let bytes = read_bounded_regular_file(&snapshot.host_path, MAX_LOCAL_SNAPSHOT_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    let container_path = Path::new(&snapshot.container_path);
    if canonical != snapshot.host_path
        || !snapshot.host_path.starts_with(project_root)
        || !container_path.is_absolute()
        || container_path.file_name().is_none()
        || container_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || local_snapshot_overlaps_runtime_mount(container_path)
        || sha256_uri(&bytes) != snapshot.digest
    {
        return Err(DevRuntimeError::project_binding());
    }
    Ok(())
}

fn local_snapshot_overlaps_runtime_mount(snapshot: &Path) -> bool {
    [
        Path::new("/run/registry"),
        Path::new("/run/secrets"),
        Path::new("/var/lib/registry/state"),
        Path::new("/var/lib/registry/audit"),
        Path::new("/var/lib/postgresql"),
        Path::new("/registryctl-stage"),
    ]
    .into_iter()
    .any(|reserved| snapshot.starts_with(reserved) || reserved.starts_with(snapshot))
}

fn validate_credential_projection(
    development: &AuthoredDevelopment,
    scenario: &AuthoredDevScenario,
    projection: &DevCredentialPublicProjection,
    files: &PreparedDevCredentialFiles,
) -> DevRuntimeResult<()> {
    let source_matches = matches!(
        (
            development.source_mode,
            scenario.oauth_profile,
            scenario
                .synthetic_source
                .as_ref()
                .and_then(|source| source.source_auth),
            &projection.source,
        ),
        (
            DevSourceMode::OperatorBound,
            DevOAuthProfile::None
                | DevOAuthProfile::Oauth2Bearer
                | DevOAuthProfile::Oauth2BearerNoExpiry,
            None,
            DevSourceCredentialProjection::OperatorBound,
        ) | (
            DevSourceMode::LocalSnapshot,
            DevOAuthProfile::None,
            None,
            DevSourceCredentialProjection::OperatorBound,
        ) | (
            DevSourceMode::Synthetic,
            DevOAuthProfile::None,
            None,
            DevSourceCredentialProjection::SyntheticUnauthenticated { .. },
        ) | (
            DevSourceMode::Synthetic,
            DevOAuthProfile::None,
            Some(SyntheticSourceAuth::StaticBearer),
            DevSourceCredentialProjection::SyntheticStaticBearer { .. },
        ) | (
            DevSourceMode::Synthetic,
            DevOAuthProfile::Oauth2Bearer,
            None,
            DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
                profile: DevOAuthCredentialProfile::Oauth2Bearer,
                ..
            },
        ) | (
            DevSourceMode::Synthetic,
            DevOAuthProfile::Oauth2BearerNoExpiry,
            None,
            DevSourceCredentialProjection::SyntheticOAuthClientCredentials {
                profile: DevOAuthCredentialProfile::Oauth2BearerNoExpiry,
                ..
            },
        )
    );
    let file_shape_matches = match development.source_mode {
        DevSourceMode::OperatorBound | DevSourceMode::LocalSnapshot => files.source.is_none(),
        DevSourceMode::Synthetic => files.source.is_some(),
    };
    if !source_matches
        || !file_shape_matches
        || files.root
            != files
                .postgres_admin_password
                .parent()
                .unwrap_or(Path::new(""))
    {
        return Err(DevRuntimeError::invalid_credentials());
    }
    Ok(())
}

fn validate_operator_secret_env(
    source_mode: DevSourceMode,
    names: &[String],
) -> DevRuntimeResult<()> {
    if (source_mode != DevSourceMode::OperatorBound && !names.is_empty())
        || names.len() > 32
        || names.windows(2).any(|pair| pair[0] >= pair[1])
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 128
                || !name.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_uppercase()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
    {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "operator source secret locators are outside the closed authored environment set",
            "use only exact authored uppercase environment secret locators",
        ));
    }
    Ok(())
}

fn select_authored_scenario<'a>(
    development: &AuthoredDevelopment,
    scenarios: &'a [AuthoredDevScenario],
) -> DevRuntimeResult<&'a AuthoredDevScenario> {
    validate_id(
        "development.default_integration",
        &development.default_integration,
    )?;
    validate_id("development.default_fixture", &development.default_fixture)?;
    let mut matches = scenarios.iter().filter(|scenario| {
        scenario.integration_id == development.default_integration
            && scenario.fixture_id == development.default_fixture
    });
    let selected = matches.next().ok_or_else(|| {
        let mut available = scenarios
            .iter()
            .map(|scenario| format!("{}.{}", scenario.integration_id, scenario.fixture_id))
            .collect::<Vec<_>>();
        available.sort();
        DevRuntimeError::new(
            DevFailureCategory::MissingDefaultScenario,
            format!(
                "development.default_integration and development.default_fixture do not name an authored scenario; available scenario ids: {}",
                available.join(", ")
            ),
            "author one exact default development scenario",
        )
    })?;
    if matches.next().is_some() {
        return Err(DevRuntimeError::new(
            DevFailureCategory::MissingDefaultScenario,
            "the authored default development scenario is ambiguous",
            "remove the duplicate integration and fixture identity",
        ));
    }
    if !selected.synthetic {
        return Err(DevRuntimeError::new(
            DevFailureCategory::MissingDefaultScenario,
            "the default development fixture must be classified synthetic",
            "select an authored synthetic fixture",
        ));
    }
    validate_id("fixture denial scenario id", &selected.denial_scenario_id)?;
    validate_id(
        "fixture authorized scenario id",
        &selected.authorized_scenario_id,
    )?;
    if selected.denial_scenario_id == selected.authorized_scenario_id {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "denial and authorized smoke scenario ids must be distinct",
            "author distinct denial and authorized smoke scenarios",
        ));
    }
    if selected.request_json.is_empty() || selected.request_json.len() > MAX_REQUEST_BODY_BYTES {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "compiled local request exceeds its closed byte contract",
            "reduce the authored development request and rebuild",
        ));
    }
    let _: serde_json::Value = parse_json_strict(&selected.request_json).map_err(|_| {
        DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "compiled local request is not strict JSON",
            "fix the authored fixture request and rebuild",
        )
    })?;
    let mut claims = BTreeSet::new();
    for claim in &selected.minimized_claim_ids {
        validate_id("minimized claim id", claim)?;
        if !claims.insert(claim) {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "minimized claim ids must be unique",
                "remove the duplicate expected claim id",
            ));
        }
    }
    if validate_sha256(&selected.expected_claim_results_sha256).is_err() {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "expected development claim result commitment is invalid",
            "rebuild the development plan from a valid authored fixture",
        ));
    }
    Ok(selected)
}

fn build_synthetic_source_plan(
    scenario: &AuthoredDevScenario,
    source_files: &PreparedDevSourceCredentialFiles,
) -> DevRuntimeResult<SyntheticSourcePlanV1> {
    let authored = scenario.synthetic_source.as_ref().ok_or_else(|| {
        DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "synthetic source mode requires the selected fixture's closed source plan",
            "add the selected synthetic fixture interactions and rebuild",
        )
    })?;
    validate_synthetic_source_request(&authored.source_request)?;
    let requires_body = matches!(
        authored.scenario,
        SyntheticSourceScenario::AuthoredResponse
            | SyntheticSourceScenario::NoMatch
            | SyntheticSourceScenario::Ambiguity
            | SyntheticSourceScenario::SubjectMismatch
    );
    if requires_body != authored.response_body.is_some() {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "synthetic source response_body presence does not match the closed scenario",
            "provide one bounded response_body only for a response-bearing scenario",
        ));
    }
    let response_body = authored
        .response_body
        .as_deref()
        .map(|bytes| {
            if bytes.is_empty() || bytes.len() > MAX_SYNTHETIC_RESPONSE_BYTES {
                return Err(DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "synthetic source response exceeds its closed byte bound",
                    "reduce the authored fixture response",
                ));
            }
            parse_json_strict(bytes).map_err(|_| {
                DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "synthetic source response_body must be strict JSON",
                    "correct the authored fixture response",
                )
            })
        })
        .transpose()?;
    let oauth = match scenario.oauth_profile {
        DevOAuthProfile::None => {
            if authored.oauth_response_case.is_some() || authored.oauth_request.is_some() {
                return Err(DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "a non-OAuth source cannot carry an OAuth request or response case",
                    "remove the OAuth interaction or select a closed OAuth profile",
                ));
            }
            None
        }
        profile @ (DevOAuthProfile::Oauth2Bearer | DevOAuthProfile::Oauth2BearerNoExpiry) => {
            let request = authored.oauth_request.as_ref().ok_or_else(|| {
                DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "an OAuth source requires one closed typed request expectation",
                    "author audience, scope, and resource expectations explicitly",
                )
            })?;
            for value in [
                request.audience.as_deref(),
                request.scope.as_deref(),
                request.resource.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                    return Err(DevRuntimeError::new(
                        DevFailureCategory::InvalidPlan,
                        "an OAuth request expectation violates its closed string bound",
                        "use a non-empty control-free OAuth expectation of at most 4096 bytes",
                    ));
                }
            }
            if matches!(
                (profile, authored.oauth_response_case),
                (
                    DevOAuthProfile::Oauth2Bearer,
                    Some(SyntheticOAuthResponseCase::UnexpectedExpiresIn)
                ) | (
                    DevOAuthProfile::Oauth2BearerNoExpiry,
                    Some(SyntheticOAuthResponseCase::MissingExpiresIn)
                )
            ) {
                return Err(DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "OAuth response case is incompatible with the selected fixed response profile",
                    "select a response case accepted by the authored OAuth profile",
                ));
            }
            Some(SyntheticOauthPlan {
                response_profile: profile,
                response_case: authored.oauth_response_case,
                request: SyntheticOauthRequest {
                    audience: request.audience.clone(),
                    scope: request.scope.clone(),
                    resource: request.resource.clone(),
                },
                secrets: SyntheticOauthSecrets {
                    client_id: synthetic_secret_ref(required_secret_basename(
                        source_files.oauth_client_id.as_ref(),
                    )?),
                    client_secret: synthetic_secret_ref(required_secret_basename(
                        source_files.oauth_client_secret.as_ref(),
                    )?),
                },
            })
        }
    };
    if oauth.is_some() && authored.source_auth.is_some() {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "synthetic source static bearer and OAuth authentication are mutually exclusive",
            "select the one authored authentication mode",
        ));
    }
    let source_auth = authored.source_auth.map(|auth| match auth {
        SyntheticSourceAuth::StaticBearer => SyntheticSourceAuthPlan::StaticBearer {
            secret: synthetic_secret_ref(
                required_secret_basename(source_files.static_bearer.as_ref())
                    .expect("credential projection validation requires static bearer"),
            ),
        },
    });

    Ok(SyntheticSourcePlanV1 {
        version: SYNTHETIC_SOURCE_PLAN_SCHEMA_V1.to_string(),
        scenario: authored.scenario,
        source_request: SyntheticSourceRequest {
            method: authored.source_request.method,
            path: authored.source_request.path.clone(),
            query: authored.source_request.query.clone(),
            headers: authored.source_request.headers.clone(),
            body: authored.source_request.body.clone(),
        },
        source_auth,
        request_encoding: scenario.request_encoding,
        oauth,
        response_body,
        secrets: SyntheticSourceSecrets {
            control_token: synthetic_secret_ref(secret_basename(&source_files.control_token)?),
            tls_certificate: synthetic_secret_ref(secret_basename(&source_files.tls_certificate)?),
            tls_private_key: synthetic_secret_ref(secret_basename(&source_files.tls_private_key)?),
        },
    })
}

fn validate_synthetic_source_request(
    request: &AuthoredSyntheticSourceRequest,
) -> DevRuntimeResult<()> {
    if !request.path.starts_with('/')
        || request.path.len() > 2048
        || request
            .path
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'#' | b'\\'))
        || request
            .path
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || matches!(
            request.path.as_str(),
            "/healthz" | "/oauth/token" | "/__registry/counters"
        )
        || request.query.len() > 16
        || request.headers.len() > 16
    {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "synthetic source request is outside the closed authored operation contract",
            "compile one bounded concrete GET or POST source request",
        ));
    }
    let valid_pair = |key: &str, value: &str| {
        !key.is_empty()
            && key.len() <= 96
            && value.len() <= 2048
            && !key
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'&' | b'=' | b'%' | b'+'))
            && !value.bytes().any(|byte| byte.is_ascii_control())
    };
    let reserved_header = |key: &str| {
        matches!(
            key,
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                | "host"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "accept-encoding"
                | "content-type"
                | "forwarded"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "x-real-ip"
                | "x-api-key"
        )
    };
    let valid_header_name = |key: &str| {
        key.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'\''
                        | b'*'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    };
    let pairs_size = request
        .query
        .iter()
        .chain(&request.headers)
        .try_fold(request.path.len(), |total, (key, value)| {
            total.checked_add(key.len())?.checked_add(value.len())
        });
    let total_size = pairs_size.and_then(|total| match &request.body {
        Some(body) => serde_json::to_vec(body)
            .ok()
            .and_then(|body| total.checked_add(body.len())),
        None => Some(total),
    });
    if request
        .query
        .iter()
        .any(|(key, value)| !valid_pair(key, value))
        || request.headers.iter().any(|(key, value)| {
            !valid_pair(key, value)
                || key != &key.to_ascii_lowercase()
                || !valid_header_name(key)
                || reserved_header(key)
        })
        || total_size.is_none_or(|total| total > 16 * 1024)
    {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "synthetic source request fields violate their closed bounds",
            "remove secret headers and reduce the compiler-owned request expectation",
        ));
    }
    Ok(())
}

fn synthetic_secret_ref(file: String) -> SyntheticSecretRef {
    SyntheticSecretRef {
        file,
        generation: 1,
    }
}

fn required_secret_basename(path: Option<&PathBuf>) -> DevRuntimeResult<String> {
    path.map(PathBuf::as_path)
        .ok_or_else(DevRuntimeError::invalid_credentials)
        .and_then(secret_basename)
}

fn secret_basename(path: &Path) -> DevRuntimeResult<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.contains(['/', '\\']))
        .map(str::to_string)
        .ok_or_else(DevRuntimeError::invalid_credentials)
}

fn build_workloads(
    project_id: &str,
    environment_id: &str,
    release: &VerifiedDevReleaseProjection,
    artifacts: &DevRuntimeArtifactInputs,
    paths: &DevRuntimePaths,
    credential_files: &PreparedDevCredentialFiles,
    options: DevWorkloadBuildOptions<'_>,
) -> DevRuntimeResult<Vec<DevWorkloadPlan>> {
    let DevWorkloadBuildOptions {
        relay_port,
        synthetic,
        local_snapshot,
        operator_source_secret_env,
    } = options;
    let identity = |lane, product, instance: &str| ProductAcceptanceIdentityV1 {
        trust_domain: ProductTrustDomainV1::Development,
        project: project_id.to_string(),
        environment: environment_id.to_string(),
        lane,
        product,
        stream: project_id.to_string(),
        instance: instance.to_string(),
    };
    let mut workloads = vec![
        DevWorkloadPlan {
            id: DevWorkloadId::RelayPublic,
            image: release.registry_relay_image.clone(),
            acceptance_identity: Some(identity(
                ProductAcceptanceLaneV1::RelayPublic,
                ProductAcceptanceProductV1::RegistryRelay,
                "relay-public",
            )),
            host_endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), relay_port)),
            prepare_state_store: Some(product_action(
                DevWorkloadId::RelayPublic,
                "prepare-state-store",
                &release.relay_public_prepare,
                artifacts,
                paths,
                credential_files,
            )?),
            initialize_state: Some(product_action(
                DevWorkloadId::RelayPublic,
                "initialize-state",
                &release.relay_public_initialize,
                artifacts,
                paths,
                credential_files,
            )?),
            command: release.relay_public_serve.command.clone(),
            health_probe: release.relay_public_health_probe.clone(),
            environment_passthrough: Vec::new(),
            mounts: product_action_mounts(
                DevWorkloadId::RelayPublic,
                &release.relay_public_serve,
                artifacts,
                paths,
                credential_files,
            )?,
            hardening: None,
        },
        DevWorkloadPlan {
            id: DevWorkloadId::RelayConsultation,
            image: release.registry_relay_image.clone(),
            acceptance_identity: Some(identity(
                ProductAcceptanceLaneV1::RelayConsultation,
                ProductAcceptanceProductV1::RegistryRelay,
                "relay-consultation",
            )),
            host_endpoint: None,
            prepare_state_store: Some(product_action(
                DevWorkloadId::RelayConsultation,
                "prepare-state-store",
                &release.relay_consultation_prepare,
                artifacts,
                paths,
                credential_files,
            )?),
            initialize_state: Some(product_action(
                DevWorkloadId::RelayConsultation,
                "initialize-state",
                &release.relay_consultation_initialize,
                artifacts,
                paths,
                credential_files,
            )?),
            command: release.relay_consultation_serve.command.clone(),
            health_probe: release.relay_consultation_health_probe.clone(),
            environment_passthrough: operator_source_secret_env.to_vec(),
            mounts: product_action_mounts(
                DevWorkloadId::RelayConsultation,
                &release.relay_consultation_serve,
                artifacts,
                paths,
                credential_files,
            )?,
            hardening: None,
        },
        DevWorkloadPlan {
            id: DevWorkloadId::Postgresql,
            image: release.postgresql_image.clone(),
            acceptance_identity: None,
            host_endpoint: None,
            prepare_state_store: Some(postgresql_staging_action(release, paths, credential_files)?),
            initialize_state: Some(postgresql_bootstrap_action(release, paths)),
            command: release.postgresql_serve.command.clone(),
            health_probe: release.postgresql_health_probe.clone(),
            environment_passthrough: release.postgresql_server_environment.clone(),
            mounts: postgresql_serve_mounts(release, paths),
            hardening: Some(release.postgresql_hardening.clone()),
        },
    ];
    if let Some(source) = &credential_files.source {
        let consultation = workloads
            .iter_mut()
            .find(|workload| workload.id == DevWorkloadId::RelayConsultation)
            .ok_or_else(DevRuntimeError::image_lock)?;
        consultation.mounts.push(secret_file_mount(
            &source.tls_certificate,
            DEV_SYNTHETIC_SOURCE_CA_CONTAINER_PATH,
        ));
    }
    if let Some(snapshot) = local_snapshot {
        for workload_id in [DevWorkloadId::RelayPublic, DevWorkloadId::RelayConsultation] {
            let workload = workloads
                .iter_mut()
                .find(|workload| workload.id == workload_id)
                .ok_or_else(DevRuntimeError::image_lock)?;
            workload.mounts.push(project_file_mount(
                &snapshot.host_path,
                &snapshot.container_path,
            ));
        }
    }
    if synthetic {
        workloads.push(DevWorkloadPlan {
            id: DevWorkloadId::SyntheticSource,
            // The fixed source is a closed subcommand in the released Relay
            // image, not an independently selected or mutable fourth image.
            image: release.registry_relay_image.clone(),
            acceptance_identity: None,
            host_endpoint: None,
            prepare_state_store: None,
            initialize_state: None,
            command: vec![
                "registry-relay".to_string(),
                "synthetic-source".to_string(),
                "--plan".to_string(),
                SYNTHETIC_SOURCE_PLAN_CONTAINER_PATH.to_string(),
            ],
            health_probe: vec![
                "registry-relay".to_string(),
                "synthetic-source".to_string(),
                "probe".to_string(),
                "--plan".to_string(),
                SYNTHETIC_SOURCE_PLAN_CONTAINER_PATH.to_string(),
            ],
            environment_passthrough: Vec::new(),
            mounts: synthetic_source_mounts(
                paths,
                credential_files
                    .source
                    .as_ref()
                    .ok_or_else(DevRuntimeError::invalid_credentials)?,
            ),
            hardening: None,
        });
    }
    Ok(workloads)
}

struct DevWorkloadBuildOptions<'a> {
    relay_port: u16,
    synthetic: bool,
    local_snapshot: Option<&'a AuthoredLocalSnapshot>,
    operator_source_secret_env: &'a [String],
}

fn postgresql_staged_path(root: &Path, file_id: &str) -> PathBuf {
    let file_name = if file_id == "postgresql-bootstrap-environment" {
        "postgresql-bootstrap-environment.env"
    } else {
        file_id
    };
    root.join(file_name)
}

fn product_environment_file<'a>(
    files: &'a PreparedDevCredentialFiles,
    workload: DevWorkloadId,
    projection: &DevRuntimeActionProjection,
) -> DevRuntimeResult<&'a PreparedDevActionCredentialFile> {
    let expected_environment = match workload {
        DevWorkloadId::RelayPublic => "relay-public-environment",
        DevWorkloadId::RelayConsultation => "relay-consultation-environment",
        DevWorkloadId::Postgresql | DevWorkloadId::SyntheticSource => {
            return Err(DevRuntimeError::image_lock());
        }
    };
    if projection.environment_files.as_slice() != [expected_environment] {
        return Err(DevRuntimeError::image_lock());
    }
    match (workload, projection.command.last().map(String::as_str)) {
        (DevWorkloadId::RelayPublic, Some("prepare_state_store")) => {
            Ok(&files.relay_public_prepare)
        }
        (DevWorkloadId::RelayPublic, Some("initialize_state")) => {
            Ok(&files.relay_public_initialize)
        }
        (DevWorkloadId::RelayPublic, Some("serve" | "verify_state")) => {
            Ok(&files.relay_public_serve)
        }
        (DevWorkloadId::RelayConsultation, Some("prepare_state_store")) => {
            Ok(&files.relay_consultation_prepare)
        }
        (DevWorkloadId::RelayConsultation, Some("initialize_state")) => {
            Ok(&files.relay_consultation_initialize)
        }
        (DevWorkloadId::RelayConsultation, Some("serve" | "verify_state")) => {
            Ok(&files.relay_consultation_serve)
        }
        _ => Err(DevRuntimeError::image_lock()),
    }
}

fn product_secret_path<'a>(
    files: &'a PreparedDevCredentialFiles,
    file_id: &str,
) -> DevRuntimeResult<&'a Path> {
    match file_id {
        "postgresql-tls-certificate" => Ok(&files.postgres_tls_certificate),
        _ => Err(DevRuntimeError::image_lock()),
    }
}

fn product_artifact_mount(
    workload: DevWorkloadId,
    source: DevRuntimeMountProjection,
    artifacts: &DevRuntimeArtifactInputs,
    paths: &DevRuntimePaths,
) -> DevRuntimeResult<DevWorkloadMount> {
    Ok(match source {
        DevRuntimeMountProjection::Bundle => {
            let path = match workload {
                DevWorkloadId::RelayPublic => &artifacts.relay_public_bundle,
                DevWorkloadId::RelayConsultation => &artifacts.relay_consultation_bundle,
                DevWorkloadId::Postgresql | DevWorkloadId::SyntheticSource => {
                    return Err(DevRuntimeError::image_lock());
                }
            };
            read_only_mount(path, "/run/registry/bundle")
        }
        DevRuntimeMountProjection::Anchor => {
            let path = match workload {
                DevWorkloadId::RelayPublic => &artifacts.relay_public_anchor,
                DevWorkloadId::RelayConsultation => &artifacts.relay_consultation_anchor,
                DevWorkloadId::Postgresql | DevWorkloadId::SyntheticSource => {
                    return Err(DevRuntimeError::image_lock());
                }
            };
            read_only_mount(path, "/run/registry/anchor")
        }
        DevRuntimeMountProjection::AntiRollbackState => writable_state_mount(paths, workload),
        DevRuntimeMountProjection::Audit => DevWorkloadMount {
            host_path: paths.root.join("audit").join(workload.compose_service()),
            container_path: "/var/lib/registry/audit".to_string(),
            read_only: false,
            kind: DevWorkloadMountKind::Bind,
        },
        DevRuntimeMountProjection::PostgresqlData => writable_postgresql_state_mount(paths),
    })
}

fn product_action_mounts(
    workload: DevWorkloadId,
    projection: &DevRuntimeActionProjection,
    artifacts: &DevRuntimeArtifactInputs,
    paths: &DevRuntimePaths,
    files: &PreparedDevCredentialFiles,
) -> DevRuntimeResult<Vec<DevWorkloadMount>> {
    let mut mounts = projection
        .mounts
        .iter()
        .map(|source| product_artifact_mount(workload, *source, artifacts, paths))
        .collect::<DevRuntimeResult<Vec<_>>>()?;
    mounts.push(action_credential_mount(product_environment_file(
        files, workload, projection,
    )?));
    for secret in &projection.secret_files {
        mounts.push(secret_file_mount(
            product_secret_path(files, &secret.file_id)?,
            &secret.target,
        ));
    }
    Ok(mounts)
}

fn postgresql_source_path<'a>(
    files: &'a PreparedDevCredentialFiles,
    file_id: &str,
) -> DevRuntimeResult<&'a Path> {
    match file_id {
        "postgresql-admin-password" => Ok(&files.postgres_admin_password),
        "postgresql-tls-certificate" => Ok(&files.postgres_tls_certificate),
        "postgresql-tls-private-key" => Ok(&files.postgres_tls_private_key),
        "postgresql-bootstrap-environment" => Ok(&files.postgres_bootstrap.host_path),
        _ => Err(DevRuntimeError::image_lock()),
    }
}

fn postgresql_staging_action(
    release: &VerifiedDevReleaseProjection,
    paths: &DevRuntimePaths,
    files: &PreparedDevCredentialFiles,
) -> DevRuntimeResult<DevProductActionPlan> {
    let mut projections = BTreeMap::new();
    for file in &release.postgresql_operator_files {
        if !file.allowed_owners.iter().any(|owner| owner == "999:999") {
            return Err(DevRuntimeError::image_lock());
        }
        projections.insert(
            file.id.clone(),
            (file.mode.clone(), "999".to_string(), "999".to_string()),
        );
    }
    for secret in release
        .postgresql_serve
        .secret_files
        .iter()
        .chain(&release.postgresql_bootstrap.secret_files)
    {
        projections.insert(
            secret.file_id.clone(),
            (secret.mode.clone(), secret.uid.clone(), secret.gid.clone()),
        );
    }
    if projections.len() != 4 {
        return Err(DevRuntimeError::image_lock());
    }

    let mut mounts = Vec::with_capacity(projections.len() + 1);
    let mut script = String::from("set -eu\n");
    for (file_id, (mode, uid, gid)) in projections {
        let source_target = format!("/registryctl-stage/source/{file_id}");
        let output_name = postgresql_staged_path(Path::new(""), &file_id);
        let output_name = output_name
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(DevRuntimeError::image_lock)?;
        mounts.push(read_only_mount(
            postgresql_source_path(files, &file_id)?,
            &source_target,
        ));
        script.push_str(&format!(
            "/usr/bin/install -m {mode} {source_target} /registryctl-stage/output/{output_name}\n\
             /usr/bin/chown {uid}:{gid} /registryctl-stage/output/{output_name}\n"
        ));
    }
    mounts.push(DevWorkloadMount {
        host_path: paths.postgresql_staged_files.clone(),
        container_path: "/registryctl-stage/output".to_string(),
        read_only: false,
        kind: DevWorkloadMountKind::Bind,
    });
    // Linux bind mounts preserve host ownership. This networkless stager needs
    // a read-only DAC bypass for its closed inputs and CHOWN for allowlisted outputs.
    Ok(DevProductActionPlan {
        compose_service: "registry-postgres-stage-secrets".to_string(),
        command: vec!["/bin/sh".to_string(), "-ceu".to_string(), script],
        mounts,
        private_network: false,
        hardening: Some(DevWorkloadHardening {
            user: "0:0".to_string(),
            read_only_root_filesystem: true,
            cap_drop: vec!["ALL".to_string()],
            cap_add: vec!["CHOWN".to_string(), "DAC_READ_SEARCH".to_string()],
            security_opt: vec!["no-new-privileges:true".to_string()],
            tmpfs: vec!["/tmp".to_string()],
        }),
    })
}

fn postgresql_action_mounts(
    action: &DevRuntimeActionProjection,
    paths: &DevRuntimePaths,
) -> Vec<DevWorkloadMount> {
    let mut mounts = action
        .environment_files
        .iter()
        .map(|file_id| DevWorkloadMount {
            host_path: postgresql_staged_path(&paths.postgresql_staged_files, file_id),
            container_path: postgresql_staged_path(Path::new("/run/registry"), file_id)
                .to_string_lossy()
                .into_owned(),
            read_only: true,
            kind: DevWorkloadMountKind::Secret,
        })
        .collect::<Vec<_>>();
    mounts.extend(action.secret_files.iter().map(|secret| {
        secret_file_mount(
            &postgresql_staged_path(&paths.postgresql_staged_files, &secret.file_id),
            &secret.target,
        )
    }));
    mounts
}

fn postgresql_serve_mounts(
    release: &VerifiedDevReleaseProjection,
    paths: &DevRuntimePaths,
) -> Vec<DevWorkloadMount> {
    let mut mounts = vec![writable_postgresql_state_mount(paths)];
    mounts.extend(postgresql_action_mounts(&release.postgresql_serve, paths));
    mounts
}

fn postgresql_bootstrap_action(
    release: &VerifiedDevReleaseProjection,
    paths: &DevRuntimePaths,
) -> DevProductActionPlan {
    DevProductActionPlan {
        compose_service: "registry-postgres-bootstrap".to_string(),
        command: release.postgresql_bootstrap.command.clone(),
        mounts: postgresql_action_mounts(&release.postgresql_bootstrap, paths),
        private_network: true,
        hardening: Some(release.postgresql_hardening.clone()),
    }
}

pub(crate) fn render_closed_compose(
    path: &Path,
    workloads: &[DevWorkloadPlan],
    source_mode: DevSourceMode,
) -> DevRuntimeResult<()> {
    let mut services = serde_json::Map::new();
    let operator_bound = source_mode == DevSourceMode::OperatorBound;
    for workload in workloads {
        services.insert(
            workload.id.compose_service().to_string(),
            compose_service(
                &workload.image,
                &workload.command,
                &workload.health_probe,
                &workload.mounts,
                &workload.environment_passthrough,
                workload.host_endpoint,
                ComposeServicePolicy {
                    workload: workload.id,
                    allow_egress: operator_bound && workload.id == DevWorkloadId::RelayConsultation,
                    private_network: true,
                    fixed_private_address: true,
                    hardening: workload.hardening.as_ref(),
                },
            )?,
        );
        for action in [
            workload.prepare_state_store.as_ref(),
            workload.initialize_state.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            services.insert(
                action.compose_service.clone(),
                compose_service(
                    &workload.image,
                    &action.command,
                    &[],
                    &action.mounts,
                    &[],
                    None,
                    ComposeServicePolicy {
                        workload: workload.id,
                        allow_egress: false,
                        private_network: action.private_network,
                        fixed_private_address: false,
                        hardening: action.hardening.as_ref(),
                    },
                )?,
            );
        }
    }
    let mut networks = serde_json::Map::from_iter([(
        "registry_private".to_string(),
        serde_json::json!({
            "internal": true,
            "ipam": {
                "config": [{"subnet": DEV_PRIVATE_SUBNET}]
            }
        }),
    )]);
    if operator_bound {
        networks.insert("registry_egress".to_string(), serde_json::json!({}));
    }
    let compose = serde_json::json!({
        "name": "registryctl-dev",
        "services": services,
        "networks": networks
    });
    let mut bytes = serde_json::to_vec_pretty(&compose).map_err(|_| DevRuntimeError::io())?;
    bytes.push(b'\n');
    write_owner_only(path, &bytes)
}

struct ComposeServicePolicy<'a> {
    workload: DevWorkloadId,
    allow_egress: bool,
    private_network: bool,
    fixed_private_address: bool,
    hardening: Option<&'a DevWorkloadHardening>,
}

fn compose_service(
    image: &str,
    command: &[String],
    health_probe: &[String],
    mounts: &[DevWorkloadMount],
    environment_passthrough: &[String],
    host_endpoint: Option<SocketAddr>,
    policy: ComposeServicePolicy<'_>,
) -> DevRuntimeResult<serde_json::Value> {
    let ComposeServicePolicy {
        workload,
        allow_egress,
        private_network,
        fixed_private_address,
        hardening,
    } = policy;
    let mut service = serde_json::Map::new();
    service.insert("image".to_string(), serde_json::json!(image));
    service.insert("command".to_string(), serde_json::json!(command));
    service.insert("init".to_string(), serde_json::json!(true));
    if let Some(hardening) = hardening {
        service.insert("user".to_string(), serde_json::json!(hardening.user));
        service.insert(
            "read_only".to_string(),
            serde_json::json!(hardening.read_only_root_filesystem),
        );
        service.insert(
            "security_opt".to_string(),
            serde_json::json!(hardening.security_opt),
        );
        service.insert(
            "cap_drop".to_string(),
            serde_json::json!(hardening.cap_drop),
        );
        if !hardening.cap_add.is_empty() {
            service.insert("cap_add".to_string(), serde_json::json!(hardening.cap_add));
        }
        if !hardening.tmpfs.is_empty() {
            service.insert("tmpfs".to_string(), serde_json::json!(hardening.tmpfs));
        }
    } else if workload != DevWorkloadId::Postgresql {
        let user = invoking_user_binding()?;
        service.insert("user".to_string(), serde_json::json!(user));
        service.insert(
            "security_opt".to_string(),
            serde_json::json!(["no-new-privileges:true"]),
        );
        service.insert("cap_drop".to_string(), serde_json::json!(["ALL"]));
    }
    if private_network {
        let mut networks = serde_json::Map::from_iter([(
            "registry_private".to_string(),
            if fixed_private_address {
                serde_json::json!({"ipv4_address": private_ipv4_address(workload)})
            } else {
                serde_json::json!({})
            },
        )]);
        if allow_egress {
            networks.insert("registry_egress".to_string(), serde_json::json!({}));
        }
        service.insert("networks".to_string(), serde_json::json!(networks));
    } else {
        service.insert("network_mode".to_string(), serde_json::json!("none"));
    }
    if !environment_passthrough.is_empty() {
        service.insert(
            "environment".to_string(),
            serde_json::json!(environment_passthrough),
        );
    }
    if !health_probe.is_empty() {
        let test = if matches!(
            health_probe.first().map(String::as_str),
            Some("CMD" | "CMD-SHELL" | "NONE")
        ) {
            health_probe.to_vec()
        } else {
            let mut test = vec!["CMD".to_string()];
            test.extend_from_slice(health_probe);
            test
        };
        service.insert(
            "healthcheck".to_string(),
            serde_json::json!({
                "test": test,
                "interval": "2s",
                "timeout": "2s",
                "retries": 30,
                "start_period": "2s"
            }),
        );
    }
    let volumes = mounts
        .iter()
        .map(|mount| {
            serde_json::json!({
                "type": "bind",
                "source": mount.host_path,
                "target": mount.container_path,
                "read_only": mount.read_only,
            })
        })
        .collect::<Vec<_>>();
    service.insert("volumes".to_string(), serde_json::json!(volumes));
    let env_files = mounts
        .iter()
        .filter(|mount| {
            mount.kind == DevWorkloadMountKind::Secret
                && mount
                    .host_path
                    .extension()
                    .is_some_and(|extension| extension == "env")
        })
        .map(|mount| mount.host_path.clone())
        .collect::<Vec<_>>();
    if !env_files.is_empty() {
        service.insert("env_file".to_string(), serde_json::json!(env_files));
    }
    if let Some(endpoint) = host_endpoint {
        if !endpoint.ip().is_loopback() {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "Compose renderer refuses a non-loopback development endpoint",
                "select a loopback development port",
            ));
        }
        let container_port = match workload {
            DevWorkloadId::RelayPublic => 8080,
            DevWorkloadId::RelayConsultation
            | DevWorkloadId::Postgresql
            | DevWorkloadId::SyntheticSource => {
                return Err(DevRuntimeError::new(
                    DevFailureCategory::InvalidPlan,
                    "a private development workload cannot publish a host port",
                    "remove the private workload port override",
                ));
            }
        };
        service.insert(
            "ports".to_string(),
            serde_json::json!([format!("127.0.0.1:{}:{container_port}", endpoint.port())]),
        );
    }
    Ok(serde_json::Value::Object(service))
}

#[cfg(unix)]
fn invoking_user_binding() -> DevRuntimeResult<String> {
    let uid = rustix::process::geteuid().as_raw();
    let gid = rustix::process::getegid().as_raw();
    if uid == 0 {
        return Err(DevRuntimeError::new(
            DevFailureCategory::UnsafeEnvironment,
            "development runtime refuses to run product workloads as root",
            "invoke registryctl dev as the non-root owner of the project",
        ));
    }
    Ok(format!("{uid}:{gid}"))
}

#[cfg(not(unix))]
fn invoking_user_binding() -> DevRuntimeResult<String> {
    Err(DevRuntimeError::new(
        DevFailureCategory::UnsafeEnvironment,
        "owner-only development credentials require a supported Unix user binding",
        "run registryctl dev from a supported Unix host",
    ))
}

const fn private_ipv4_address(workload: DevWorkloadId) -> &'static str {
    match workload {
        DevWorkloadId::Postgresql => "10.89.0.2",
        DevWorkloadId::SyntheticSource => "10.89.0.3",
        DevWorkloadId::RelayConsultation => "10.89.0.4",
        DevWorkloadId::RelayPublic => "10.89.0.5",
    }
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn relay_development_action(lane: &str, action: &str) -> DevRuntimeActionProjection {
    test_development_action("registry-relay", lane, action)
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn test_postgresql_secret(file_id: &str, target: &str) -> DevSecretProjection {
    DevSecretProjection {
        file_id: file_id.to_string(),
        target: target.to_string(),
        mode: "0400".to_string(),
        uid: "999".to_string(),
        gid: "999".to_string(),
    }
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn test_postgresql_operator_file(id: &str, required_keys: &[&str]) -> DevOperatorFileProjection {
    DevOperatorFileProjection {
        id: id.to_string(),
        mode: "0600".to_string(),
        allowed_owners: vec!["999:999".to_string()],
        required_keys: required_keys
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    }
}

fn product_action(
    workload: DevWorkloadId,
    action: &str,
    projection: &DevRuntimeActionProjection,
    artifacts: &DevRuntimeArtifactInputs,
    paths: &DevRuntimePaths,
    credential_files: &PreparedDevCredentialFiles,
) -> DevRuntimeResult<DevProductActionPlan> {
    Ok(DevProductActionPlan {
        compose_service: format!("{}-{action}", workload.compose_service()),
        command: projection.command.clone(),
        mounts: product_action_mounts(workload, projection, artifacts, paths, credential_files)?,
        private_network: true,
        hardening: None,
    })
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn test_development_action(binary: &str, lane: &str, action: &str) -> DevRuntimeActionProjection {
    let mut command = vec![binary.to_string(), "development-action".to_string()];
    if binary == "registry-relay" {
        command.push(lane.to_string());
    }
    command.push(action.to_string());
    let mounts = if action == "prepare_state_store" {
        vec![
            DevRuntimeMountProjection::Bundle,
            DevRuntimeMountProjection::Anchor,
            DevRuntimeMountProjection::Audit,
        ]
    } else {
        vec![
            DevRuntimeMountProjection::Bundle,
            DevRuntimeMountProjection::Anchor,
            DevRuntimeMountProjection::AntiRollbackState,
            DevRuntimeMountProjection::Audit,
        ]
    };
    let secret = |file_id: &str, target: &str| DevSecretProjection {
        file_id: file_id.to_string(),
        target: target.to_string(),
        mode: "0400".to_string(),
        uid: "65532".to_string(),
        gid: "65532".to_string(),
    };
    let mut secret_files = Vec::new();
    if lane != "relay-public" {
        secret_files.push(secret(
            "postgresql-tls-certificate",
            "/run/secrets/postgresql-ca.pem",
        ));
    }
    DevRuntimeActionProjection {
        command,
        mounts,
        environment_files: vec![format!("{lane}-environment")],
        secret_files,
    }
}

fn read_only_mount(host_path: &Path, container_path: &str) -> DevWorkloadMount {
    DevWorkloadMount {
        host_path: host_path.to_path_buf(),
        container_path: container_path.to_string(),
        read_only: true,
        kind: DevWorkloadMountKind::Bind,
    }
}

fn project_file_mount(host_path: &Path, container_path: &str) -> DevWorkloadMount {
    DevWorkloadMount {
        host_path: host_path.to_path_buf(),
        container_path: container_path.to_string(),
        read_only: true,
        kind: DevWorkloadMountKind::ProjectFile,
    }
}

fn writable_state_mount(paths: &DevRuntimePaths, workload: DevWorkloadId) -> DevWorkloadMount {
    DevWorkloadMount {
        host_path: paths.root.join("state").join(workload.compose_service()),
        container_path: "/var/lib/registry/state".to_string(),
        read_only: false,
        kind: DevWorkloadMountKind::Bind,
    }
}

fn writable_postgresql_state_mount(paths: &DevRuntimePaths) -> DevWorkloadMount {
    DevWorkloadMount {
        host_path: paths
            .root
            .join("state")
            .join(DevWorkloadId::Postgresql.compose_service()),
        container_path: "/var/lib/postgresql/data".to_string(),
        read_only: false,
        kind: DevWorkloadMountKind::Bind,
    }
}

fn secret_file_mount(host_path: &Path, container_path: &str) -> DevWorkloadMount {
    DevWorkloadMount {
        host_path: host_path.to_path_buf(),
        container_path: container_path.to_string(),
        read_only: true,
        kind: DevWorkloadMountKind::Secret,
    }
}

fn action_credential_mount(file: &PreparedDevActionCredentialFile) -> DevWorkloadMount {
    secret_file_mount(&file.host_path, &file.container_path)
}

fn validate_development_trust_material(
    artifacts: &DevRuntimeArtifactInputs,
    workloads: &[DevWorkloadPlan],
) -> DevRuntimeResult<()> {
    let lanes = [
        (
            DevWorkloadId::RelayPublic,
            &artifacts.relay_public_bundle,
            &artifacts.relay_public_anchor,
        ),
        (
            DevWorkloadId::RelayConsultation,
            &artifacts.relay_consultation_bundle,
            &artifacts.relay_consultation_anchor,
        ),
    ];
    for (workload_id, bundle, anchor_path) in lanes {
        let expected = workloads
            .iter()
            .find(|workload| workload.id == workload_id)
            .and_then(|workload| workload.acceptance_identity.as_ref())
            .ok_or_else(DevRuntimeError::development_trust)?;
        let verified = verify_config_bundle(bundle, anchor_path)
            .map_err(|_| DevRuntimeError::development_trust())?;
        if &verified.manifest.acceptance_identity != expected
            || &verified.trust_anchor.acceptance_identity != expected
            || expected.trust_domain != ProductTrustDomainV1::Development
        {
            return Err(DevRuntimeError::development_trust());
        }
    }
    Ok(())
}

fn synthetic_source_mounts(
    paths: &DevRuntimePaths,
    source: &PreparedDevSourceCredentialFiles,
) -> Vec<DevWorkloadMount> {
    let mut mounts = vec![
        read_only_mount(
            &paths.synthetic_source_plan,
            SYNTHETIC_SOURCE_PLAN_CONTAINER_PATH,
        ),
        synthetic_secret_mount(&source.control_token),
        synthetic_secret_mount(&source.tls_certificate),
        synthetic_secret_mount(&source.tls_private_key),
    ];
    if let Some(path) = &source.oauth_client_id {
        mounts.push(synthetic_secret_mount(path));
    }
    if let Some(path) = &source.oauth_client_secret {
        mounts.push(synthetic_secret_mount(path));
    }
    if let Some(path) = &source.static_bearer {
        mounts.push(synthetic_secret_mount(path));
    }
    mounts
}

fn synthetic_secret_mount(host_path: &Path) -> DevWorkloadMount {
    let file = host_path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("prepared credential descriptors have validated UTF-8 basenames");
    secret_file_mount(host_path, &format!("{SYNTHETIC_SOURCE_SECRET_ROOT}/{file}"))
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevRuntimeStateV1 {
    pub schema_version: String,
    pub binding: DevProjectBindingV1,
    pub plan_digest: String,
    pub compose_project: String,
    pub compose_file: PathBuf,
    pub compose_digest: String,
    pub generated_artifact_root: PathBuf,
    pub plan_file: PathBuf,
    pub source_mode: DevSourceMode,
    pub workloads: Vec<DevWorkloadId>,
}

impl DevRuntimeStateV1 {
    fn from_plan(plan: &DevRuntimePlan) -> Self {
        Self {
            schema_version: DEV_RUNTIME_STATE_SCHEMA_V1.to_string(),
            binding: plan.binding.clone(),
            plan_digest: plan.plan_digest.clone(),
            compose_project: plan.lifecycle.compose_project.clone(),
            compose_file: plan.lifecycle.compose_file.clone(),
            compose_digest: plan.compose_digest.clone(),
            generated_artifact_root: plan
                .artifacts
                .compose_file
                .parent()
                .expect("validated Compose file has a parent")
                .to_path_buf(),
            plan_file: plan.paths.plan_file.clone(),
            source_mode: plan.source_mode,
            workloads: plan.lifecycle.status_services.clone(),
        }
    }

    fn validate_for(&self, plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
        self.validate_identity(plan)?;
        if self.plan_digest != plan.plan_digest
            || self.compose_project != plan.lifecycle.compose_project
            || self.compose_file != plan.lifecycle.compose_file
            || self.compose_digest != plan.compose_digest
            || self.plan_file != plan.paths.plan_file
            || self.source_mode != plan.source_mode
            || self.workloads != plan.lifecycle.status_services
        {
            return Err(DevRuntimeError::project_binding());
        }
        Ok(())
    }

    fn validate_identity(&self, plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
        let registry_root = plan
            .paths
            .root
            .ancestors()
            .nth(3)
            .ok_or_else(DevRuntimeError::project_binding)?;
        let compose_file =
            fs::canonicalize(&self.compose_file).map_err(|_| DevRuntimeError::project_binding())?;
        let generated_artifact_root = fs::canonicalize(&self.generated_artifact_root)
            .map_err(|_| DevRuntimeError::project_binding())?;
        let expected_generated_root = plan
            .artifacts
            .compose_file
            .parent()
            .ok_or_else(DevRuntimeError::project_binding)?;
        let project_root = registry_root
            .parent()
            .ok_or_else(DevRuntimeError::project_binding)?;
        let workload_set = self.workloads.iter().copied().collect::<BTreeSet<_>>();
        if self.schema_version != DEV_RUNTIME_STATE_SCHEMA_V1
            || self.binding != plan.binding
            || self.compose_project != plan.lifecycle.compose_project
            || !compose_file.starts_with(registry_root)
            || self.generated_artifact_root != expected_generated_root
            || generated_artifact_root != expected_generated_root
            || !valid_generated_artifact_root(project_root, expected_generated_root)
            || !compose_file.starts_with(&generated_artifact_root)
            || self.plan_file != plan.paths.plan_file
            || self.workloads.is_empty()
            || workload_set.len() != self.workloads.len()
        {
            return Err(DevRuntimeError::project_binding());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevImageAvailability {
    Local,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevRuntimeHealth {
    Running,
    Stopped,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevDoctorReport {
    pub docker_installed: bool,
    pub daemon_available: bool,
    pub compose_supported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevWorkloadStatus {
    pub workload: DevWorkloadId,
    pub state: DevRuntimeHealthWire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevRuntimeHealthWire {
    Running,
    Stopped,
    Degraded,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevStatusReport {
    pub schema_version: String,
    pub binding: DevProjectBindingV1,
    pub workloads: Vec<DevWorkloadStatus>,
    pub source_mode: DevSourceMode,
    pub relay_api_url: String,
    pub records_denied_command: Option<String>,
    pub records_request_command: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevProductLogSummary {
    pub workload: DevWorkloadId,
    /// Confirms that the bound product has a Compose log stream without
    /// copying product log values into Registryctl or its report.
    pub available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevLogsReport {
    pub schema_version: String,
    pub binding: DevProjectBindingV1,
    pub products: Vec<DevProductLogSummary>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DevSmokeStatus {
    Denied,
    Authorized,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevSmokeScenarioResult {
    pub scenario_id: String,
    pub status: DevSmokeStatus,
    /// Present only for the controlled synthetic source. Operator-bound
    /// sources expose no trustworthy internal counter surface.
    pub token_counter_delta: Option<u64>,
    pub source_counter_delta: Option<u64>,
    pub minimized_claim_ids: Vec<String>,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevSmokeReportV1 {
    pub schema_version: String,
    pub project: String,
    pub environment: String,
    pub results: Vec<DevSmokeScenarioResult>,
    pub passed: bool,
}

impl DevSmokeReportV1 {
    fn validate(&self, plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
        if self.schema_version != DEV_SMOKE_REPORT_SCHEMA_V1
            || self.project != plan.binding.project
            || self.environment != plan.binding.environment
        {
            return Err(DevRuntimeError::smoke());
        }
        if plan.records_request.is_none() {
            return (self.results.is_empty() && self.passed)
                .then_some(())
                .ok_or_else(DevRuntimeError::smoke);
        }
        if self.results.len() != 2 {
            return Err(DevRuntimeError::smoke());
        }
        let denial = self.results.iter().find(|result| {
            result.scenario_id == plan.lifecycle.smoke_denial_scenario
                && result.status == DevSmokeStatus::Denied
        });
        let authorized = self.results.iter().find(|result| {
            result.scenario_id == plan.lifecycle.smoke_authorized_scenario
                && result.status == DevSmokeStatus::Authorized
        });
        let Some(denial) = denial else {
            return Err(DevRuntimeError::smoke());
        };
        let Some(authorized) = authorized else {
            return Err(DevRuntimeError::smoke());
        };
        if denial.token_counter_delta.is_some()
            || denial.source_counter_delta.is_some()
            || authorized.token_counter_delta.is_some()
            || authorized.source_counter_delta.is_some()
            || !denial.minimized_claim_ids.is_empty()
            || !authorized.minimized_claim_ids.is_empty()
            || !denial.passed
            || !authorized.passed
            || !self.passed
        {
            return Err(DevRuntimeError::smoke());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevStartupReport {
    pub endpoints: Vec<SocketAddr>,
    pub relay_api_url: String,
    pub source_mode: DevSourceMode,
    pub records_denied_command: Option<String>,
    pub records_request_command: Option<String>,
    pub smoke_command: String,
    pub logs_command: String,
    pub down_command: String,
    pub disposable_notice: &'static str,
}

pub trait DevRuntimeBackend {
    fn doctor(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<DevDoctorReport>;
    fn image_availability(&mut self, image: &str) -> DevRuntimeResult<DevImageAvailability>;
    fn pull_image(&mut self, image: &str) -> DevRuntimeResult<()>;
    fn health(&mut self, state: &DevRuntimeStateV1) -> DevRuntimeResult<DevRuntimeHealth>;
    fn start(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
        detach: bool,
    ) -> DevRuntimeResult<()>;
    fn attach(
        &mut self,
        _plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<()> {
        Err(DevRuntimeError::backend_contract())
    }
    fn status(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevWorkloadStatus>>;
    fn logs(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevProductLogSummary>>;
    fn smoke(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<DevSmokeReportV1>;
    fn down(&mut self, state: &DevRuntimeStateV1, timeout_seconds: u16) -> DevRuntimeResult<()>;
}

/// Concrete backend for the released Docker Compose development runtime.
///
/// All invocations use fixed arguments derived from the verified plan. Secret
/// values remain in owner-only files and are never placed in argv.
#[derive(Default)]
pub struct DockerComposeBackend;

impl DockerComposeBackend {
    fn docker(args: &[String]) -> DevRuntimeResult<Output> {
        Command::new("docker").args(args).output().map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::DockerUnavailable,
                "Docker could not be invoked",
                "start the Docker service and retry",
            )
        })
    }

    fn docker_success(args: &[String]) -> DevRuntimeResult<Output> {
        let output = Self::docker(args)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(DevRuntimeError::new(
                DevFailureCategory::DockerUnavailable,
                "a closed Docker operation failed",
                "inspect Docker service diagnostics and retry",
            ))
        }
    }

    fn compose_args(state: &DevRuntimeStateV1) -> Vec<String> {
        vec![
            "compose".to_string(),
            "--project-name".to_string(),
            state.compose_project.clone(),
            "--file".to_string(),
            state.compose_file.to_string_lossy().into_owned(),
        ]
    }

    fn compose_success(
        state: &DevRuntimeStateV1,
        operation: impl IntoIterator<Item = String>,
    ) -> DevRuntimeResult<Output> {
        let mut args = Self::compose_args(state);
        args.extend(operation);
        Self::docker_success(&args)
    }

    fn compose_attached(
        state: &DevRuntimeStateV1,
        operation: impl IntoIterator<Item = String>,
    ) -> DevRuntimeResult<()> {
        let mut args = Self::compose_args(state);
        args.extend(operation);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| DevRuntimeError::io())?;
        runtime.block_on(async {
            let mut child = tokio::process::Command::new("docker")
                .args(&args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| {
                    DevRuntimeError::new(
                        DevFailureCategory::DockerUnavailable,
                        "Docker Compose could not be started",
                        "start the Docker service and retry",
                    )
                })?;
            tokio::select! {
                status = child.wait() => {
                    let status = status.map_err(|_| DevRuntimeError::backend_contract())?;
                    if status.success() {
                        Err(DevRuntimeError::new(
                            DevFailureCategory::Startup,
                            "attached development runtime stopped",
                            "inspect the value-free runtime status and retry",
                        ))
                    } else {
                        Err(DevRuntimeError::new(
                            DevFailureCategory::Startup,
                            "attached Docker Compose exited unsuccessfully",
                            "inspect Docker Compose diagnostics and retry",
                        ))
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|_| DevRuntimeError::backend_contract())?;
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                    Ok(())
                }
            }
        })
    }

    fn product_workloads(plan: &DevRuntimePlan) -> impl Iterator<Item = &DevWorkloadPlan> {
        plan.workloads
            .iter()
            .filter(|workload| workload.acceptance_identity.is_some())
    }

    fn request_records(
        plan: &DevRuntimePlan,
        authorized: bool,
    ) -> DevRuntimeResult<(DevSmokeStatus, Vec<String>)> {
        let records = plan
            .records_request
            .as_ref()
            .ok_or_else(DevRuntimeError::smoke)?;
        let endpoint = plan.relay_public_endpoint()?;
        let url = format!(
            "http://{endpoint}/v1/datasets/{}/entities/{}/records/{}",
            encode_path_segment(&records.dataset_id),
            encode_path_segment(&records.entity_id),
            encode_path_segment(&records.record_id),
        );
        let agent = ureq::AgentBuilder::new().build();
        let mut request = agent.get(&url).set("Data-Purpose", &records.purpose);
        if authorized {
            let token_path = plan
                .prepared_credential_files()?
                .relay_match_token
                .as_ref()
                .ok_or_else(DevRuntimeError::smoke)?;
            let token = read_owner_only_regular_file(token_path, 16 * 1024)
                .map_err(|_| DevRuntimeError::smoke())?;
            let token = std::str::from_utf8(&token).map_err(|_| DevRuntimeError::smoke())?;
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match request.call() {
            Ok(response) if authorized && (200..300).contains(&response.status()) => {
                Ok((DevSmokeStatus::Authorized, Vec::new()))
            }
            Err(ureq::Error::Status(status, _)) if !authorized && matches!(status, 401 | 403) => {
                Ok((DevSmokeStatus::Denied, Vec::new()))
            }
            _ => Err(DevRuntimeError::smoke()),
        }
    }
}

pub(crate) fn supporting_up_operation(services: Vec<String>) -> Vec<String> {
    let mut operation = vec![
        "up".to_string(),
        "--detach".to_string(),
        "--wait".to_string(),
        "--wait-timeout".to_string(),
        "60".to_string(),
    ];
    operation.extend(services);
    operation
}

#[derive(Deserialize)]
struct ComposePsEntry {
    #[serde(rename = "Service")]
    service: String,
    #[serde(rename = "State")]
    state: String,
    #[serde(rename = "Health", default)]
    health: String,
}

fn parse_compose_ps(bytes: &[u8]) -> DevRuntimeResult<Vec<ComposePsEntry>> {
    parse_json_strict(bytes).map_err(|_| DevRuntimeError::backend_contract())
}

fn compose_entry_health(entry: &ComposePsEntry) -> DevRuntimeHealthWire {
    if entry.state == "running" && entry.health == "healthy" {
        DevRuntimeHealthWire::Running
    } else if matches!(entry.state.as_str(), "exited" | "stopped" | "created") {
        DevRuntimeHealthWire::Stopped
    } else {
        DevRuntimeHealthWire::Degraded
    }
}

pub(crate) fn classify_compose_ps_health(
    bytes: &[u8],
    expected_services: &[&str],
) -> DevRuntimeResult<DevRuntimeHealth> {
    let entries = parse_compose_ps(bytes)?;
    let expected = expected_services.iter().copied().collect::<BTreeSet<_>>();
    let actual = entries
        .iter()
        .map(|entry| entry.service.as_str())
        .collect::<BTreeSet<_>>();
    Ok(
        if actual == expected
            && entries
                .iter()
                .all(|entry| compose_entry_health(entry) == DevRuntimeHealthWire::Running)
        {
            DevRuntimeHealth::Running
        } else if entries.is_empty()
            || (actual == expected
                && entries
                    .iter()
                    .all(|entry| compose_entry_health(entry) == DevRuntimeHealthWire::Stopped))
        {
            DevRuntimeHealth::Stopped
        } else {
            DevRuntimeHealth::Degraded
        },
    )
}

impl DevRuntimeBackend for DockerComposeBackend {
    fn doctor(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<DevDoctorReport> {
        let docker_installed = Command::new("docker")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        let daemon_available = docker_installed
            && Self::docker(&["info".to_string()]).is_ok_and(|output| output.status.success());
        let compose_supported = daemon_available
            && Self::docker(&[
                "compose".to_string(),
                "version".to_string(),
                "--short".to_string(),
            ])
            .is_ok_and(|output| {
                output.status.success()
                    && std::str::from_utf8(&output.stdout)
                        .ok()
                        .is_some_and(|value| {
                            compose_version_satisfies(value, &plan.minimum_compose_version)
                        })
            });
        Ok(DevDoctorReport {
            docker_installed,
            daemon_available,
            compose_supported,
        })
    }

    fn image_availability(&mut self, image: &str) -> DevRuntimeResult<DevImageAvailability> {
        let output = Self::docker(&[
            "image".to_string(),
            "inspect".to_string(),
            image.to_string(),
        ])?;
        Ok(if output.status.success() {
            DevImageAvailability::Local
        } else {
            DevImageAvailability::Absent
        })
    }

    fn pull_image(&mut self, image: &str) -> DevRuntimeResult<()> {
        Self::docker_success(&["pull".to_string(), image.to_string()]).map(|_| ())
    }

    fn health(&mut self, state: &DevRuntimeStateV1) -> DevRuntimeResult<DevRuntimeHealth> {
        let output = Self::compose_success(
            state,
            [
                "ps".to_string(),
                "--all".to_string(),
                "--format".to_string(),
                "json".to_string(),
            ],
        )?;
        let expected = state
            .workloads
            .iter()
            .map(|workload| workload.compose_service())
            .collect::<Vec<_>>();
        classify_compose_ps_health(&output.stdout, &expected)
    }

    fn start(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
        detach: bool,
    ) -> DevRuntimeResult<()> {
        let postgresql = plan
            .workloads
            .iter()
            .find(|workload| workload.id == DevWorkloadId::Postgresql)
            .ok_or_else(DevRuntimeError::backend_contract)?;
        let staging = postgresql
            .prepare_state_store
            .as_ref()
            .ok_or_else(DevRuntimeError::backend_contract)?;
        let mut stage_operation = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--no-deps".to_string(),
            staging.compose_service.clone(),
        ];
        stage_operation.extend(staging.command.iter().cloned());
        Self::compose_success(state, stage_operation)?;
        Self::compose_success(
            state,
            supporting_up_operation(vec![DevWorkloadId::Postgresql
                .compose_service()
                .to_string()]),
        )?;
        let bootstrap = postgresql
            .initialize_state
            .as_ref()
            .ok_or_else(DevRuntimeError::backend_contract)?;
        let mut bootstrap_operation = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--no-deps".to_string(),
            bootstrap.compose_service.clone(),
        ];
        bootstrap_operation.extend(bootstrap.command.iter().cloned());
        Self::compose_success(state, bootstrap_operation)?;

        let supporting = plan
            .workloads
            .iter()
            .filter(|workload| {
                workload.acceptance_identity.is_none() && workload.id != DevWorkloadId::Postgresql
            })
            .map(|workload| workload.id.compose_service().to_string())
            .collect::<Vec<_>>();
        if !supporting.is_empty() {
            let operation = supporting_up_operation(supporting);
            Self::compose_success(state, operation)?;
        }
        for workload in Self::product_workloads(plan) {
            for action in [
                workload.prepare_state_store.as_ref(),
                workload.initialize_state.as_ref(),
            ] {
                let action = action.ok_or_else(DevRuntimeError::backend_contract)?;
                let mut operation = vec![
                    "run".to_string(),
                    "--rm".to_string(),
                    "--no-deps".to_string(),
                    action.compose_service.clone(),
                ];
                operation.extend(action.command.iter().cloned());
                Self::compose_success(state, operation)?;
            }
        }
        let services = Self::product_workloads(plan)
            .map(|workload| workload.id.compose_service().to_string())
            .collect::<Vec<_>>();
        let operation = if detach {
            supporting_up_operation(services)
        } else {
            let mut operation = vec!["up".to_string()];
            operation.extend(services);
            operation
        };
        if detach {
            Self::compose_success(state, operation).map(|_| ())
        } else {
            Self::compose_attached(state, operation)
        }
    }

    fn attach(&mut self, plan: &DevRuntimePlan, state: &DevRuntimeStateV1) -> DevRuntimeResult<()> {
        let mut operation = vec!["up".to_string()];
        operation.extend(
            Self::product_workloads(plan).map(|workload| workload.id.compose_service().to_string()),
        );
        Self::compose_attached(state, operation)
    }

    fn status(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevWorkloadStatus>> {
        let output = Self::compose_success(
            state,
            [
                "ps".to_string(),
                "--all".to_string(),
                "--format".to_string(),
                "json".to_string(),
            ],
        )?;
        let entries = parse_compose_ps(&output.stdout)?;
        let states = entries
            .into_iter()
            .map(|entry| (entry.service.clone(), compose_entry_health(&entry)))
            .collect::<BTreeMap<_, _>>();
        Ok(plan
            .lifecycle
            .status_services
            .iter()
            .map(|workload| DevWorkloadStatus {
                workload: *workload,
                state: states
                    .get(workload.compose_service())
                    .copied()
                    .unwrap_or(DevRuntimeHealthWire::Stopped),
            })
            .collect())
    }

    fn logs(
        &mut self,
        plan: &DevRuntimePlan,
        state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<Vec<DevProductLogSummary>> {
        let output = Self::compose_success(state, ["ps".to_string(), "--services".to_string()])?;
        let available = std::str::from_utf8(&output.stdout)
            .map_err(|_| DevRuntimeError::backend_contract())?
            .lines()
            .collect::<BTreeSet<_>>();
        Ok(plan
            .lifecycle
            .log_services
            .iter()
            .map(|workload| DevProductLogSummary {
                workload: *workload,
                available: available.contains(workload.compose_service()),
            })
            .collect())
    }

    fn smoke(
        &mut self,
        plan: &DevRuntimePlan,
        _state: &DevRuntimeStateV1,
    ) -> DevRuntimeResult<DevSmokeReportV1> {
        let results = if plan.records_request.is_some() {
            let (denial_status, denial_claims) = Self::request_records(plan, false)?;
            let (authorized_status, authorized_claims) = Self::request_records(plan, true)?;
            vec![
                DevSmokeScenarioResult {
                    scenario_id: plan.lifecycle.smoke_denial_scenario.clone(),
                    status: denial_status,
                    token_counter_delta: None,
                    source_counter_delta: None,
                    minimized_claim_ids: denial_claims,
                    passed: true,
                },
                DevSmokeScenarioResult {
                    scenario_id: plan.lifecycle.smoke_authorized_scenario.clone(),
                    status: authorized_status,
                    token_counter_delta: None,
                    source_counter_delta: None,
                    minimized_claim_ids: authorized_claims,
                    passed: true,
                },
            ]
        } else {
            Vec::new()
        };
        Ok(DevSmokeReportV1 {
            schema_version: DEV_SMOKE_REPORT_SCHEMA_V1.to_string(),
            project: plan.binding.project.clone(),
            environment: plan.binding.environment.clone(),
            results,
            passed: true,
        })
    }

    fn down(&mut self, state: &DevRuntimeStateV1, timeout_seconds: u16) -> DevRuntimeResult<()> {
        Self::compose_success(
            state,
            [
                "down".to_string(),
                "--volumes".to_string(),
                "--remove-orphans".to_string(),
                "--timeout".to_string(),
                timeout_seconds.to_string(),
            ],
        )
        .map(|_| ())
    }
}

pub struct DevRuntimeController<B> {
    backend: B,
}

pub fn diagnose_dev_runtime(plan: &DevRuntimePlan) -> DevRuntimeResult<DevDoctorReport> {
    validate_plan_compose(plan)?;
    let mut backend = DockerComposeBackend;
    let report = backend.doctor(plan)?;
    validate_doctor_report(&report)?;
    Ok(report)
}

fn validate_doctor_report(doctor: &DevDoctorReport) -> DevRuntimeResult<()> {
    if !doctor.docker_installed {
        return Err(DevRuntimeError::new(
            DevFailureCategory::DockerMissing,
            "Docker is not available",
            "install Docker using the documented development prerequisite",
        ));
    }
    if !doctor.daemon_available {
        return Err(DevRuntimeError::new(
            DevFailureCategory::DockerUnavailable,
            "Docker is installed but its daemon is unavailable",
            "start the Docker service and retry",
        ));
    }
    if !doctor.compose_supported {
        return Err(DevRuntimeError::new(
            DevFailureCategory::ComposeUnsupported,
            "Docker Compose does not satisfy the released minimum",
            "install the documented Docker Compose version",
        ));
    }
    Ok(())
}

impl<B: DevRuntimeBackend> DevRuntimeController<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    pub fn start(
        &mut self,
        plan: &DevRuntimePlan,
        _detach: bool,
    ) -> DevRuntimeResult<DevStartupReport> {
        let mut candidate = CandidateArtifactGuard::new(plan)?;
        validate_plan_compose(plan)?;
        let doctor = self.backend.doctor(plan)?;
        validate_doctor_report(&doctor)?;

        if plan.paths.state_file.exists() {
            let existing_plan =
                load_bound_dev_runtime_plan(&bound_project_root(plan)?, &plan.binding.environment)?;
            if existing_plan.artifacts.compose_file.parent() == plan.artifacts.compose_file.parent()
            {
                candidate.disarm();
            }
            let existing = load_bound_state_for_down(&existing_plan)?;
            match self.backend.health(&existing)? {
                DevRuntimeHealth::Running if same_runtime_semantics(&existing_plan, plan) => {
                    return Ok(startup_report(&existing_plan));
                }
                DevRuntimeHealth::Running
                | DevRuntimeHealth::Stopped
                | DevRuntimeHealth::Degraded => {
                    self.backend
                        .down(&existing, plan.lifecycle.shutdown_timeout_seconds)?;
                    remove_bound_runtime_by_identity(&existing_plan, &existing)?;
                }
            }
        }
        check_loopback_ports(plan)?;
        for image in plan.image_refs() {
            match self.backend.image_availability(image)? {
                DevImageAvailability::Local => {}
                DevImageAvailability::Absent => self.backend.pull_image(image).map_err(|_| {
                    DevRuntimeError::new(
                        DevFailureCategory::ImageUnavailable,
                        "a released digest-locked development image is unavailable",
                        "load the documented released image archive with docker load and retry",
                    )
                })?,
            }
        }
        let state = materialize_runtime(plan)?;
        candidate.disarm();
        if let Err(error) = self.backend.start(plan, &state, true) {
            if self
                .backend
                .down(&state, plan.lifecycle.shutdown_timeout_seconds)
                .is_ok()
            {
                let _ = remove_bound_runtime_by_identity(plan, &state);
            }
            return Err(DevRuntimeError::new(
                error.category,
                "development startup failed",
                error.remediation,
            ));
        }
        Ok(startup_report(plan))
    }

    /// Attach to an already started runtime after the caller has displayed
    /// [`DevStartupReport`]. Normal Ctrl-C performs bounded Compose shutdown
    /// and removes only the validated bound disposable runtime.
    pub fn attach(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
        let bound_plan =
            load_bound_dev_runtime_plan(&bound_project_root(plan)?, &plan.binding.environment)?;
        let state = load_bound_state(&bound_plan)?;
        let attached = self.backend.attach(&bound_plan, &state);
        self.backend
            .down(&state, bound_plan.lifecycle.shutdown_timeout_seconds)?;
        let remove = remove_bound_runtime_by_identity(&bound_plan, &state);
        attached?;
        remove
    }

    pub fn status(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<DevStatusReport> {
        let state = load_bound_state(plan)?;
        let workloads = self.backend.status(plan, &state)?;
        validate_workload_statuses(plan, &workloads)?;
        Ok(DevStatusReport {
            schema_version: DEV_STATUS_REPORT_SCHEMA_V1.to_string(),
            binding: plan.binding.clone(),
            workloads,
            source_mode: plan.source_mode,
            relay_api_url: format!("http://{}", plan.relay_public_endpoint()?),
            records_denied_command: plan.records_denied_command(),
            records_request_command: plan.records_request_command(),
        })
    }

    pub fn logs(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<DevLogsReport> {
        let state = load_bound_state(plan)?;
        let products = self.backend.logs(plan, &state)?;
        validate_log_summaries(plan, &products)?;
        Ok(DevLogsReport {
            schema_version: DEV_LOGS_REPORT_SCHEMA_V1.to_string(),
            binding: plan.binding.clone(),
            products,
        })
    }

    pub fn smoke(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<DevSmokeReportV1> {
        let state = load_bound_state(plan)?;
        let report = self.backend.smoke(plan, &state)?;
        report.validate(plan)?;
        Ok(report)
    }

    pub fn down(&mut self, plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
        let state = load_bound_state_for_down(plan)?;
        self.backend
            .down(&state, plan.lifecycle.shutdown_timeout_seconds)?;
        remove_bound_runtime_by_identity(plan, &state)
    }
}

fn same_runtime_semantics(existing: &DevRuntimePlan, candidate: &DevRuntimePlan) -> bool {
    existing.binding == candidate.binding
        && existing.build_manifest_digest == candidate.build_manifest_digest
        && existing.records_request_digest == candidate.records_request_digest
        && existing.local_snapshot_digest == candidate.local_snapshot_digest
        && existing.release_tag == candidate.release_tag
        && existing.minimum_compose_version == candidate.minimum_compose_version
        && existing.source_mode == candidate.source_mode
        && existing.scenario == candidate.scenario
        && existing
            .workloads
            .iter()
            .map(|workload| {
                (
                    workload.id,
                    workload.image.as_str(),
                    workload.command.as_slice(),
                    workload.health_probe.as_slice(),
                    workload.environment_passthrough.as_slice(),
                    workload
                        .mounts
                        .iter()
                        .map(|mount| {
                            (
                                mount.container_path.as_str(),
                                mount.read_only,
                                mount.kind,
                                (mount.kind == DevWorkloadMountKind::ProjectFile)
                                    .then_some(mount.host_path.as_path()),
                            )
                        })
                        .collect::<Vec<_>>(),
                    workload.host_endpoint,
                )
            })
            .eq(candidate.workloads.iter().map(|workload| {
                (
                    workload.id,
                    workload.image.as_str(),
                    workload.command.as_slice(),
                    workload.health_probe.as_slice(),
                    workload.environment_passthrough.as_slice(),
                    workload
                        .mounts
                        .iter()
                        .map(|mount| {
                            (
                                mount.container_path.as_str(),
                                mount.read_only,
                                mount.kind,
                                (mount.kind == DevWorkloadMountKind::ProjectFile)
                                    .then_some(mount.host_path.as_path()),
                            )
                        })
                        .collect::<Vec<_>>(),
                    workload.host_endpoint,
                )
            }))
}

struct CandidateArtifactGuard {
    project_root: PathBuf,
    generated_root: PathBuf,
    armed: bool,
}

impl CandidateArtifactGuard {
    fn from_roots(project_root: PathBuf, generated_root: PathBuf) -> DevRuntimeResult<Self> {
        if !valid_generated_artifact_root(&project_root, &generated_root) {
            return Err(DevRuntimeError::project_binding());
        }
        Ok(Self {
            project_root,
            generated_root,
            armed: true,
        })
    }

    fn new(plan: &DevRuntimePlan) -> DevRuntimeResult<Self> {
        let project_root = bound_project_root(plan)?;
        let generated_root = plan
            .artifacts
            .compose_file
            .parent()
            .ok_or_else(DevRuntimeError::project_binding)?
            .to_path_buf();
        Self::from_roots(project_root, generated_root)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

fn bound_project_root(plan: &DevRuntimePlan) -> DevRuntimeResult<PathBuf> {
    let project_root = plan
        .paths
        .root
        .ancestors()
        .nth(4)
        .ok_or_else(DevRuntimeError::project_binding)?
        .to_path_buf();
    if plan.paths.root
        != project_root
            .join(DEV_ROOT)
            .join(&plan.binding.environment)
            .join(stable_runtime_id(&plan.binding)?)
    {
        return Err(DevRuntimeError::project_binding());
    }
    Ok(project_root)
}

impl Drop for CandidateArtifactGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_generated_dev_artifact(&self.project_root, &self.generated_root);
        }
    }
}

fn materialize_runtime(plan: &DevRuntimePlan) -> DevRuntimeResult<DevRuntimeStateV1> {
    if plan.paths.root.exists() {
        return Err(DevRuntimeError::project_binding());
    }
    let result = (|| {
        for workload in &plan.workloads {
            for mount in workload
                .mounts
                .iter()
                .filter(|mount| !mount.read_only && mount.kind == DevWorkloadMountKind::Bind)
            {
                create_owner_only_dir(&mount.host_path)?;
            }
        }
        create_owner_only_dir(&plan.paths.postgresql_staged_files)?;
        let materialized = plan
            .credentials
            .as_ref()
            .ok_or_else(DevRuntimeError::invalid_credentials)?
            .materialize_owner_only(&plan.paths.credentials)
            .map_err(|_| DevRuntimeError::io())?;
        if Some(materialized) != plan.credential_files {
            return Err(DevRuntimeError::backend_contract());
        }
        if plan.source_mode == DevSourceMode::Synthetic {
            let source_plan = plan
                .synthetic_source_plan
                .as_ref()
                .ok_or_else(DevRuntimeError::io)?;
            let mut source_plan_bytes =
                serde_json::to_vec(source_plan).map_err(|_| DevRuntimeError::io())?;
            source_plan_bytes.push(b'\n');
            write_owner_only(&plan.paths.synthetic_source_plan, &source_plan_bytes)?;
        }
        match (
            plan.records_request.as_ref(),
            &plan.prepared_credential_files()?.relay_match_token,
            &plan.prepared_credential_files()?.relay_no_match_token,
        ) {
            (Some(records), Some(match_token_path), Some(_)) => {
                for value in [
                    records.dataset_id.as_str(),
                    records.entity_id.as_str(),
                    records.record_id.as_str(),
                    records.purpose.as_str(),
                ] {
                    validate_curl_literal(value)?;
                }
                let match_token = read_owner_only_regular_file(match_token_path, 16 * 1024)
                    .map_err(|_| DevRuntimeError::io())?;
                let match_token = std::str::from_utf8(&match_token)
                    .map_err(|_| DevRuntimeError::invalid_credentials())?;
                validate_curl_literal(match_token)?;
                let relay_endpoint = plan.relay_public_endpoint()?;
                let records_url = format!(
                    "http://{relay_endpoint}/v1/datasets/{}/entities/{}/records/{}",
                    encode_path_segment(&records.dataset_id),
                    encode_path_segment(&records.entity_id),
                    encode_path_segment(&records.record_id),
                );
                let records_request = format!(
                    "url = \"{records_url}\"\nrequest = \"GET\"\nheader = \"Authorization: Bearer {match_token}\"\nheader = \"Data-Purpose: {}\"\nsilent\nshow-error\nfail\n",
                    records.purpose
                );
                write_owner_only(
                    &plan.paths.records_request_config,
                    records_request.as_bytes(),
                )?;
                let records_denied = format!(
                    "url = \"{records_url}\"\nrequest = \"GET\"\nheader = \"Data-Purpose: {}\"\ninclude\nsilent\nshow-error\n",
                    records.purpose
                );
                write_owner_only(&plan.paths.records_denied_config, records_denied.as_bytes())?;
            }
            (None, None, None) => {}
            _ => return Err(DevRuntimeError::invalid_credentials()),
        }
        let mut plan_bytes = serde_json::to_vec(plan).map_err(|_| DevRuntimeError::io())?;
        plan_bytes.push(b'\n');
        write_owner_only(&plan.paths.plan_file, &plan_bytes)?;
        let state = DevRuntimeStateV1::from_plan(plan);
        let mut state_bytes = serde_json::to_vec(&state).map_err(|_| DevRuntimeError::io())?;
        state_bytes.push(b'\n');
        write_owner_only(&plan.paths.state_file, &state_bytes)?;
        Ok(state)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&plan.paths.root);
    }
    result
}

fn load_bound_state(plan: &DevRuntimePlan) -> DevRuntimeResult<DevRuntimeStateV1> {
    let state = load_bound_state_for_down(plan)?;
    state.validate_for(plan)?;
    validate_local_snapshot(plan)?;
    Ok(state)
}

fn load_bound_state_for_down(plan: &DevRuntimePlan) -> DevRuntimeResult<DevRuntimeStateV1> {
    refuse_ambiguous_state(plan)?;
    let bytes = read_owner_only_regular_file(&plan.paths.state_file, MAX_RUNTIME_STATE_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    let state: DevRuntimeStateV1 =
        parse_json_strict(&bytes).map_err(|_| DevRuntimeError::project_binding())?;
    state.validate_identity(plan)?;
    let compose_bytes = read_bounded_regular_file(&state.compose_file, MAX_COMPOSE_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    if sha256_uri(&compose_bytes) != state.compose_digest {
        return Err(DevRuntimeError::project_binding());
    }
    Ok(state)
}

fn validate_plan_compose(plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
    let bytes = read_bounded_regular_file(&plan.lifecycle.compose_file, MAX_COMPOSE_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    if sha256_uri(&bytes) != plan.compose_digest {
        return Err(DevRuntimeError::project_binding());
    }
    validate_local_snapshot(plan)?;
    Ok(())
}

pub(crate) fn validate_local_snapshot(plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
    let project_mounts = plan
        .workloads
        .iter()
        .flat_map(|workload| {
            workload
                .mounts
                .iter()
                .filter(|mount| mount.kind == DevWorkloadMountKind::ProjectFile)
                .map(move |mount| (workload.id, mount))
        })
        .collect::<Vec<_>>();
    let action_has_project_mount = plan.workloads.iter().any(|workload| {
        [
            workload.prepare_state_store.as_ref(),
            workload.initialize_state.as_ref(),
        ]
        .into_iter()
        .flatten()
        .flat_map(|action| &action.mounts)
        .any(|mount| mount.kind == DevWorkloadMountKind::ProjectFile)
    });
    let Some(expected_digest) = &plan.local_snapshot_digest else {
        return if plan.source_mode == DevSourceMode::LocalSnapshot
            || !project_mounts.is_empty()
            || action_has_project_mount
        {
            Err(DevRuntimeError::project_binding())
        } else {
            Ok(())
        };
    };
    if plan.source_mode != DevSourceMode::LocalSnapshot {
        return Err(DevRuntimeError::project_binding());
    }
    let project_root = bound_project_root(plan)?;
    if action_has_project_mount
        || project_mounts.len() != 2
        || project_mounts[0].0 != DevWorkloadId::RelayPublic
        || project_mounts[1].0 != DevWorkloadId::RelayConsultation
        || project_mounts[0].1 != project_mounts[1].1
    {
        return Err(DevRuntimeError::project_binding());
    }
    let mount = project_mounts[0].1;
    let canonical =
        fs::canonicalize(&mount.host_path).map_err(|_| DevRuntimeError::project_binding())?;
    let bytes = read_bounded_regular_file(&mount.host_path, MAX_LOCAL_SNAPSHOT_BYTES)
        .map_err(|_| DevRuntimeError::project_binding())?;
    if !mount.read_only
        || !mount.host_path.starts_with(&project_root)
        || canonical != mount.host_path
        || sha256_uri(&bytes) != *expected_digest
    {
        return Err(DevRuntimeError::project_binding());
    }
    Ok(())
}

fn refuse_ambiguous_state(plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
    let Some(environment_root) = plan.paths.root.parent() else {
        return Err(DevRuntimeError::project_binding());
    };
    if !environment_root.exists() {
        return Ok(());
    }
    let metadata =
        fs::symlink_metadata(environment_root).map_err(|_| DevRuntimeError::project_binding())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DevRuntimeError::project_binding());
    }
    let mut matching = 0usize;
    let entries = fs::read_dir(environment_root).map_err(|_| DevRuntimeError::project_binding())?;
    for entry in entries {
        let entry = entry.map_err(|_| DevRuntimeError::project_binding())?;
        let state_path = entry.path().join(RUNTIME_STATE_FILE);
        if !state_path.exists() {
            continue;
        }
        let bytes = read_bounded_regular_file(&state_path, MAX_RUNTIME_STATE_BYTES)
            .map_err(|_| DevRuntimeError::project_binding())?;
        let state: DevRuntimeStateV1 =
            parse_json_strict(&bytes).map_err(|_| DevRuntimeError::project_binding())?;
        if state.binding.project == plan.binding.project
            && state.binding.environment == plan.binding.environment
        {
            matching += 1;
        }
    }
    if matching > 1 {
        return Err(DevRuntimeError::new(
            DevFailureCategory::AmbiguousRuntime,
            "multiple development runtimes claim this project and environment",
            "inspect the owner-only runtime state and remove the stale binding explicitly",
        ));
    }
    Ok(())
}

fn remove_bound_runtime_by_identity(
    plan: &DevRuntimePlan,
    state: &DevRuntimeStateV1,
) -> DevRuntimeResult<()> {
    state.validate_identity(plan)?;
    let expected_parent = plan.paths.root.parent().ok_or_else(DevRuntimeError::io)?;
    if plan.paths.root != expected_parent.join(stable_runtime_id(&plan.binding)?) {
        return Err(DevRuntimeError::project_binding());
    }
    let registry_root = plan
        .paths
        .root
        .ancestors()
        .nth(3)
        .ok_or_else(DevRuntimeError::project_binding)?;
    let project_root = registry_root
        .parent()
        .ok_or_else(DevRuntimeError::project_binding)?;
    let generated_root = state.generated_artifact_root.clone();
    fs::remove_dir_all(&plan.paths.root).map_err(|_| DevRuntimeError::io())?;
    remove_generated_dev_artifact(project_root, &generated_root)
}

fn validate_workload_statuses(
    plan: &DevRuntimePlan,
    statuses: &[DevWorkloadStatus],
) -> DevRuntimeResult<()> {
    let expected = plan
        .lifecycle
        .status_services
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = statuses
        .iter()
        .map(|status| status.workload)
        .collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != statuses.len() {
        return Err(DevRuntimeError::new(
            DevFailureCategory::BackendContract,
            "runtime status did not cover the exact bound workload set",
            "inspect Docker Compose and retry registryctl dev status",
        ));
    }
    Ok(())
}

fn validate_log_summaries(
    plan: &DevRuntimePlan,
    summaries: &[DevProductLogSummary],
) -> DevRuntimeResult<()> {
    let expected = plan
        .lifecycle
        .log_services
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let actual = summaries
        .iter()
        .map(|summary| summary.workload)
        .collect::<BTreeSet<_>>();
    if actual != expected
        || actual.len() != summaries.len()
        || summaries.iter().any(|summary| !summary.available)
    {
        return Err(DevRuntimeError::new(
            DevFailureCategory::BackendContract,
            "runtime logs violated the bounded value-free product summary contract",
            "retry registryctl dev logs with the released runtime",
        ));
    }
    Ok(())
}

fn check_loopback_ports(plan: &DevRuntimePlan) -> DevRuntimeResult<()> {
    let mut listeners = Vec::new();
    for endpoint in plan.public_endpoints() {
        if !endpoint.ip().is_loopback() {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "development public endpoint is not bound to loopback",
                "remove the non-loopback development port override",
            ));
        }
        let listener = TcpListener::bind(endpoint).map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::PortCollision,
                "a development loopback port is unavailable",
                "author an unused loopback port override and retry",
            )
        })?;
        listeners.push(listener);
    }
    Ok(())
}

fn startup_report(plan: &DevRuntimePlan) -> DevStartupReport {
    DevStartupReport {
        endpoints: plan.public_endpoints(),
        relay_api_url: format!(
            "http://{}",
            plan.relay_public_endpoint()
                .expect("validated development plan has a public Relay endpoint")
        ),
        source_mode: plan.source_mode,
        records_denied_command: plan.records_denied_command(),
        records_request_command: plan.records_request_command(),
        smoke_command: plan.smoke_command(),
        logs_command: plan.logs_command(),
        down_command: plan.down_command(),
        disposable_notice:
            "local trust, credentials, and state are disposable development inputs, not production inputs",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevFailureCategory {
    InvalidPlan,
    MissingDefaultScenario,
    UnsafeEnvironment,
    ProjectBinding,
    AmbiguousRuntime,
    StaleBuild,
    InvalidImageLock,
    DockerMissing,
    DockerUnavailable,
    ComposeUnsupported,
    ImageUnavailable,
    PortCollision,
    Startup,
    BackendContract,
    SmokeFailed,
    Io,
}

impl DevFailureCategory {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPlan => "registryctl.dev.invalid_plan",
            Self::MissingDefaultScenario => "registryctl.dev.missing_default_scenario",
            Self::UnsafeEnvironment => "registryctl.dev.unsafe_environment",
            Self::ProjectBinding => "registryctl.dev.project_binding",
            Self::AmbiguousRuntime => "registryctl.dev.ambiguous_runtime",
            Self::StaleBuild => "registryctl.dev.stale_build",
            Self::InvalidImageLock => "registryctl.dev.invalid_image_lock",
            Self::DockerMissing => "registryctl.dev.docker_missing",
            Self::DockerUnavailable => "registryctl.dev.docker_unavailable",
            Self::ComposeUnsupported => "registryctl.dev.compose_unsupported",
            Self::ImageUnavailable => "registryctl.dev.image_unavailable",
            Self::PortCollision => "registryctl.dev.port_collision",
            Self::Startup => "registryctl.dev.startup",
            Self::BackendContract => "registryctl.dev.backend_contract",
            Self::SmokeFailed => "registryctl.dev.smoke_failed",
            Self::Io => "registryctl.dev.io",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DevRuntimeError {
    pub category: DevFailureCategory,
    pub summary: String,
    pub remediation: String,
}

impl DevRuntimeError {
    pub fn new(
        category: DevFailureCategory,
        summary: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            category,
            summary: summary.into(),
            remediation: remediation.into(),
        }
    }

    fn image_lock() -> Self {
        Self::new(
            DevFailureCategory::InvalidImageLock,
            "released development image lock is invalid",
            "reinstall Registryctl from a verified Registry Stack release",
        )
    }

    fn project_binding() -> Self {
        Self::new(
            DevFailureCategory::ProjectBinding,
            "development runtime state is not bound uniquely to this project",
            "select the project that owns the runtime or inspect its owner-only state",
        )
    }

    fn development_trust() -> Self {
        Self::new(
            DevFailureCategory::InvalidPlan,
            "development bundle or anchor is not bound to the exact disposable development identity",
            "rebuild the selected environment's disposable development trust material",
        )
    }

    fn invalid_credentials() -> Self {
        Self::new(
            DevFailureCategory::InvalidPlan,
            "development credential closure does not match the compiled runtime plan",
            "rebuild the environment and regenerate its disposable development credentials",
        )
    }

    fn backend_contract() -> Self {
        Self::new(
            DevFailureCategory::BackendContract,
            "Docker Compose returned output outside the closed runtime contract",
            "install the released supported Docker Compose version and retry",
        )
    }

    fn smoke() -> Self {
        Self::new(
            DevFailureCategory::SmokeFailed,
            "development smoke did not satisfy the closed denial and authorization contract",
            "run registryctl dev logs and inspect the value-free product summaries",
        )
    }

    fn io() -> Self {
        Self::new(
            DevFailureCategory::Io,
            "development runtime state could not be updated safely",
            "check owner permissions under .registry-stack/dev and retry",
        )
    }
}

impl fmt::Display for DevRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {}; remediation: {}",
            self.category.code(),
            self.summary,
            self.remediation,
        )
    }
}

impl std::error::Error for DevRuntimeError {}

pub type DevRuntimeResult<T> = Result<T, DevRuntimeError>;

fn validate_artifact_inputs(
    root: &Path,
    artifacts: &DevRuntimeArtifactInputs,
) -> DevRuntimeResult<()> {
    for path in [
        &artifacts.compose_file,
        &artifacts.relay_public_bundle,
        &artifacts.relay_public_anchor,
        &artifacts.relay_consultation_bundle,
        &artifacts.relay_consultation_anchor,
    ] {
        let canonical = fs::canonicalize(path).map_err(|_| {
            DevRuntimeError::new(
                DevFailureCategory::StaleBuild,
                "a generated development artifact is missing",
                "rebuild the selected environment before starting development",
            )
        })?;
        if !canonical.starts_with(root.join(".registry-stack")) {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "a generated development artifact escaped the project runtime directory",
                "rebuild the selected environment with Registryctl",
            ));
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| DevRuntimeError::io())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(DevRuntimeError::new(
                DevFailureCategory::InvalidPlan,
                "a generated development artifact is not a real file or directory",
                "remove the unsafe artifact and rebuild the selected environment",
            ));
        }
    }
    Ok(())
}

fn validate_runtime_ancestors(root: &Path, target: &Path) -> DevRuntimeResult<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| DevRuntimeError::project_binding())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(DevRuntimeError::project_binding());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(DevRuntimeError::project_binding()),
        }
    }
    Ok(())
}

struct DevPlanDigestInput<'a> {
    binding: &'a DevProjectBindingV1,
    build_manifest_digest: &'a str,
    release: &'a VerifiedDevReleaseProjection,
    source_mode: DevSourceMode,
    scenario: &'a DevScenarioPlan,
    workloads: &'a [DevWorkloadPlan],
    lifecycle: &'a DevLifecycleBindings,
    artifacts: &'a DevRuntimeArtifactInputs,
    compose_digest: &'a str,
    records_request_digest: Option<&'a str>,
    local_snapshot_digest: Option<&'a str>,
    synthetic_source_plan: Option<&'a SyntheticSourcePlanV1>,
}

fn plan_digest(input: DevPlanDigestInput<'_>) -> DevRuntimeResult<String> {
    #[derive(Serialize)]
    struct DigestInput<'a> {
        binding: &'a DevProjectBindingV1,
        build_manifest_digest: &'a str,
        release: &'a VerifiedDevReleaseProjection,
        source_mode: DevSourceMode,
        scenario: &'a DevScenarioPlan,
        workloads: &'a [DevWorkloadPlan],
        lifecycle: &'a DevLifecycleBindings,
        artifacts: &'a DevRuntimeArtifactInputs,
        compose_digest: &'a str,
        records_request_digest: Option<&'a str>,
        local_snapshot_digest: Option<&'a str>,
        synthetic_source_plan_digest: Option<String>,
    }
    let synthetic_source_plan_digest = input
        .synthetic_source_plan
        .map(|plan| {
            serde_json::to_vec(plan)
                .map(|bytes| sha256_uri(&bytes))
                .map_err(|_| DevRuntimeError::io())
        })
        .transpose()?;
    let bytes = serde_json::to_vec(&DigestInput {
        binding: input.binding,
        build_manifest_digest: input.build_manifest_digest,
        release: input.release,
        source_mode: input.source_mode,
        scenario: input.scenario,
        workloads: input.workloads,
        lifecycle: input.lifecycle,
        artifacts: input.artifacts,
        compose_digest: input.compose_digest,
        records_request_digest: input.records_request_digest,
        local_snapshot_digest: input.local_snapshot_digest,
        synthetic_source_plan_digest,
    })
    .map_err(|_| DevRuntimeError::io())?;
    Ok(sha256_uri(&bytes))
}

pub(crate) fn stable_runtime_id(binding: &DevProjectBindingV1) -> DevRuntimeResult<String> {
    let bytes = serde_json::to_vec(binding).map_err(|_| DevRuntimeError::io())?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(&digest[..8]))
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn validate_image_ref(value: &str, repository: &str) -> DevRuntimeResult<()> {
    let Some(digest) = value.strip_prefix(&format!("{repository}@sha256:")) else {
        return Err(DevRuntimeError::image_lock());
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(DevRuntimeError::image_lock());
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(
    test,
    allow(dead_code, reason = "used by direct-module integration tests")
)]
fn valid_release_tag(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    let parts = version.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn compose_version_satisfies(actual: &str, minimum: &str) -> bool {
    parse_version(actual)
        .zip(parse_version(minimum))
        .is_some_and(|(actual, minimum)| actual >= minimum)
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .split(['-', '+'])
        .next()?
        .parse()
        .ok()?;
    Some((major, minor, patch))
}

fn validate_sha256(value: &str) -> Result<(), ()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(());
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_id(field: &str, value: &str) -> DevRuntimeResult<()> {
    let mut bytes = value.bytes();
    let valid = value.len() <= MAX_ID_BYTES
        && matches!(bytes.next(), Some(first) if first.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'));
    if !valid {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            format!("{field} is not a valid closed identifier"),
            "correct the authored identifier and retry",
        ));
    }
    Ok(())
}

fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|_| ())?;
    deserializer.end().map_err(|_| ())?;
    Ok(value)
}

pub(crate) fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let file = open_read_only_no_follow(path)?;
    read_bounded_open_file(file, max_bytes, false)
}

fn read_bounded_open_file(
    mut file: File,
    max_bytes: u64,
    require_owner_only: bool,
) -> std::io::Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe bounded file",
        ));
    }
    #[cfg(unix)]
    if require_owner_only {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "owner-only file has group or other permissions",
            ));
        }
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bounded file exceeded limit",
        ));
    }
    Ok(bytes)
}

fn read_owner_only_regular_file(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let file = open_read_only_no_follow(path)?;
    read_bounded_open_file(file, max_bytes, true)
}

#[cfg(unix)]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    Ok(File::from(descriptor))
}

#[cfg(windows)]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe bounded file",
        ));
    }
    File::open(path)
}

fn create_owner_only_dir(path: &Path) -> DevRuntimeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path).map_err(|_| DevRuntimeError::io())?;
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| DevRuntimeError::io())?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path).map_err(|_| DevRuntimeError::io())?;
    Ok(())
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> DevRuntimeResult<()> {
    let parent = path.parent().ok_or_else(DevRuntimeError::io)?;
    create_owner_only_dir(parent)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| DevRuntimeError::io())?;
    file.write_all(bytes).map_err(|_| DevRuntimeError::io())?;
    file.sync_all().map_err(|_| DevRuntimeError::io())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| DevRuntimeError::io())?;
    }
    Ok(())
}

fn validate_curl_literal(value: &str) -> DevRuntimeResult<()> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
    {
        return Err(DevRuntimeError::new(
            DevFailureCategory::InvalidPlan,
            "development request value cannot be represented safely",
            "use identifiers and purposes without quotes or control characters",
        ));
    }
    Ok(())
}

fn encode_path_segment(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn shell_quote_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
