// SPDX-License-Identifier: Apache-2.0
//! Deterministic Registry Server project checking and artifact generation.
//!
//! This crate owns filesystem orchestration and report rendering only. Model
//! parsing, validation, compilation, and artifact generation remain in
//! `registry-server`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_server::compiler::module_digest_with_assets;
use registry_server::contract::{FieldTypeSource, ModuleAssetSource, ModuleLockSource};
use registry_server::migration_plan::ReviewedMigrationRecovery;
use registry_server::package::{
    inspect_package_integrity, CompiledRegistryChangeClass, MigrationInspectionPlanKind,
    MigrationInspectionSummary, PackageBuildRequest, PackageError, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, PreparedPackage, SignaturePolicy,
    FIXTURE_JOURNEYS_PATH, MAX_PACKAGE_SOURCE_FILE_BYTES, MAX_RHAI_PLANNER_PATH_BYTES,
    MAX_RHAI_PLANNER_SOURCE_BYTES,
};
use registry_server::runtime_config::RuntimeConfigError;
use registry_server::tooling::{classify_registry_diff, CompiledRegistryDiff, DiffClassification};
use registry_server::{
    compile_project_with_assets, parse_module_yaml, parse_project_yaml, CompileFailure,
    CompileProfile, CompiledRegistry, Diagnostic, DiagnosticSeverity, GeneratedArtifact,
    GeneratedArtifacts, RegistryModule, RegistryProject,
};
use serde::Serialize;
use serde_json::{json, Value};

mod apply_lifecycle;
mod data_lifecycle;
mod doctor;
mod history_erasure_lifecycle;
mod history_rebaseline_lifecycle;
mod package_inspection;
mod package_lifecycle;
mod project_migration;
mod reconcile_lifecycle;
mod request_retention;
mod reviewed_migrations;
mod test_lifecycle;
mod webhook_lifecycle;

use apply_lifecycle::{ApplyLifecycleError, ApplyLifecycleRequest};
use data_lifecycle::{
    DataExportRequest, DataImportRequest, DataLifecycleError, DataValidateRequest,
};
use history_erasure_lifecycle::{
    HistoryErasureLifecycleError, HistoryErasureLifecycleOutcome, HistoryErasureLifecycleRequest,
};
use history_rebaseline_lifecycle::{
    HistoryRebaselineLifecycleError, HistoryRebaselineLifecycleOutcome,
    HistoryRebaselineLifecycleRequest,
};
use package_inspection::{
    inspect_runtime_package, inspect_runtime_predecessor_package, RuntimePackageInspectionError,
};
use package_lifecycle::{PackageLifecycleError, PackageLifecycleState};
use reconcile_lifecycle::{
    ReconcileLifecycleError, ReconcileLifecycleOutcome, ReconcileLifecycleRequest,
};
use registry_server::data::DataError;
use registry_server::migration_reconcile::{ReconcileError, ReconcileOutcome};
use request_retention::{
    RequestRetentionCliError, RequestRetentionDryRunOutcome, RequestRetentionEraseOutcome,
    RequestRetentionListOutcome,
};
use test_lifecycle::{TestLifecycleError, TestLifecycleRequest};
use webhook_lifecycle::{
    WebhookLifecycleError, WebhookListOutcome, WebhookReplayOutcome, WebhookSampleOutcome,
};

const DOMAIN_REFUSAL_EXIT: u8 = 1;
const USAGE_EXIT: u8 = 2;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;
// Keep ctl-authored project and module source capture aligned with the
// schema-test package rederivation ceiling so source-size refusals occur
// before runtime secret resolution or database rehearsal. Broader package-file
// limits still apply to fixture journeys and generated package artifacts.
const AUTHORED_SOURCE_REDERIVATION_MAX_BYTES: u64 = 1024 * 1024;
const MAX_DERIVED_SQL_ASSET_BYTES: u64 = 256 * 1024;
const MAX_PLANNER_TEST_REQUEST_BYTES: u64 = 64 * 1024;
const PLANNER_TEST_DEADLINE: Duration = Duration::from_secs(1);
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Parser)]
#[command(
    name = "registry-serverctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Registry Server project checking and deterministic generation"
)]
struct Cli {
    /// Emit the selected command's report in this format.
    #[arg(long, value_enum, global = true, default_value_t)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a domain-neutral example authoring project in a new directory.
    Init(InitArgs),
    /// Validate a Registry Server authoring project without opening a database.
    Check(CheckArgs),
    /// Maintain deterministic authoring project metadata.
    Project(ProjectArgs),
    /// Write selected compiler artifacts to a new directory.
    Generate(GenerateArgs),
    /// Explain compiled model, access, route, or event inventories.
    Explain(ExplainArgs),
    /// Compare an authoring candidate with a rederived closed package.
    Diff(DiffArgs),
    /// Build a deterministic production-profile signing input or publish its externally signed package.
    Package(PackageArgs),
    /// Execute the production schema-test journey suite for one unsigned package candidate.
    Test(TestArgs),
    /// Apply one already signed package using the configured migration authority.
    Apply(ApplyArgs),
    /// Verify configured startup dependencies without binding a listener.
    Doctor(DoctorArgs),
    /// Verify one configured package without opening runtime dependencies.
    Verify(VerifyArgs),
    /// Inspect configured migration lifecycle metadata.
    Migration(MigrationArgs),
    /// Run bounded, audited retained-history maintenance.
    History(HistoryArgs),
    /// Validate, import, or export data through authenticated Registry HTTP APIs.
    Data(DataArgs),
    /// Inspect and operate configured webhook deliveries.
    Webhook(WebhookArgs),
    /// Inspect and erase eligible change-request retention detail.
    RequestRetention(RequestRetentionArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// New directory that will receive the example project closure.
    #[arg(value_name = "DESTINATION")]
    destination: PathBuf,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,
    /// Exit unsuccessfully when any authoring finding needs review, including access warnings.
    #[arg(long)]
    deny_findings: bool,
}

#[derive(Debug, Args)]
struct ProjectArgs {
    #[command(subcommand)]
    command: ProjectCommand,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Compute and write module source digests in registry.yaml.
    Lock(ProjectLockArgs),
    /// Migrate the retired singular Manifest projection to the plural resource model.
    Migrate(ProjectMigrateArgs),
    /// Run one captured Rhai request planner with bounded synthetic JSON.
    PlannerTest(ProjectPlannerTestArgs),
}

#[derive(Debug, Args)]
struct ProjectLockArgs {
    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Refuse when registry.yaml is not already locked instead of rewriting it.
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
struct ProjectMigrateArgs {
    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Write the reviewed migration. Without this flag, only a diff is emitted.
    #[arg(long)]
    write: bool,
}

#[derive(Debug, Args)]
struct ProjectPlannerTestArgs {
    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Compiled change-request entity whose Rhai planner will run.
    #[arg(long, value_name = "ENTITY")]
    entity: String,

    /// Bounded strict JSON object containing synthetic request fields.
    #[arg(long, value_name = "JSON_FILE")]
    request: PathBuf,
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// Artifact family to write.
    #[arg(value_name = "ARTIFACT", value_enum)]
    artifact: ArtifactSelector,

    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,

    /// New directory that will receive exactly the generated artifact inventory.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Compiled inventory to explain.
    #[arg(value_name = "SUBJECT", value_enum)]
    subject: ExplainSubject,

    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,
    /// For access only: bounded JSON with synthetic claims. Performs no token verification or record access.
    #[arg(long, value_name = "JSON_FILE")]
    scenario: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct PackageCandidateArgs {
    /// Registry Server project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Stable deployment database identity recorded in the package.
    #[arg(long, value_name = "ID")]
    database_id: String,

    /// Runtime configuration selecting the verified active baseline for a successor.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    baseline_runtime_config: Option<PathBuf>,

    /// Directory containing reviewed migration descriptors and evidence in package layout. Used identically by test and package; requires a verified baseline.
    #[arg(long, value_name = "DIRECTORY", requires = "baseline_runtime_config")]
    reviewed_migrations: Option<PathBuf>,

    /// Production signature threshold. Local packages require zero.
    #[arg(long, default_value_t = 0, value_name = "COUNT")]
    signature_threshold: u16,

    /// Allowed package-signing key id. Repeat once per trust-anchor key.
    #[arg(
        long = "signature-key-id",
        value_name = "KEY_ID",
        allow_hyphen_values = true
    )]
    signature_key_ids: Vec<String>,
}

#[derive(Debug, Args)]
struct PackageArgs {
    #[command(flatten)]
    candidate: PackageCandidateArgs,

    /// Exact managed-catalog SHA-256 produced by the reviewed PostgreSQL rehearsal.
    /// Read from the schema-test receipt when it is not supplied.
    #[arg(long, value_name = "SHA256")]
    schema_fingerprint: Option<String>,

    /// Canonical receipt from a successful schema test of this exact candidate.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    test_receipt: PathBuf,

    /// JSON document containing externally produced package signatures.
    #[arg(long, value_name = "FILE")]
    signatures: Option<PathBuf>,

    /// New build directory containing signing-input.json and, once approved, package/.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct TestArgs {
    #[command(flatten)]
    candidate: PackageCandidateArgs,

    /// Absolute runtime configuration for test database access and secret resolution.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute schema-test credential binding document.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    credentials: PathBuf,

    /// New canonical schema-test receipt file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Absolute runtime configuration for deployment identity, trust, roles, and database access.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute target package directory.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Activate sequence one in an uninitialized Registry database.
    #[arg(long)]
    initial: bool,

    /// Reviewed backup binding and absolute local artifact as BINDING_PATH=ABSOLUTE_FILE.
    #[arg(long = "backup", value_name = "BINDING_PATH=ABSOLUTE_FILE")]
    backups: Vec<String>,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct MigrationArgs {
    #[command(subcommand)]
    command: MigrationCommand,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    #[command(subcommand)]
    command: HistoryCommand,
}

#[derive(Debug, Args)]
struct DataArgs {
    #[command(subcommand)]
    command: DataCommand,
}

#[derive(Debug, Args)]
struct WebhookArgs {
    #[command(subcommand)]
    command: WebhookCommand,
}

#[derive(Debug, Args)]
struct RequestRetentionArgs {
    #[command(subcommand)]
    command: RequestRetentionCommand,
}

#[derive(Debug, Subcommand)]
enum WebhookCommand {
    /// Render one deterministic exact CloudEvents request with synthetic values.
    Sample(WebhookSampleArgs),
    /// List bounded value-free pending, dead-lettered, and expired delivery metadata.
    List(WebhookListArgs),
    /// Replay one eligible retained dead-letter using optimistic generation binding.
    Replay(WebhookReplayArgs),
}

#[derive(Debug, Subcommand)]
enum RequestRetentionCommand {
    /// List bounded value-free change-request retention rows.
    List(RequestRetentionListArgs),
    /// Count exactly what one request retention erase would remove.
    DryRun(RequestRetentionExactArgs),
    /// Erase eligible payload detail for one exact request proposal version.
    Erase(RequestRetentionExactArgs),
}

#[derive(Debug, Args)]
struct RequestRetentionListArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Limit the value-free listing to one compiled change-request entity.
    #[arg(long, value_name = "ENTITY")]
    request_entity: Option<String>,

    /// Cursor returned by the previous bounded list response.
    #[arg(long, value_name = "CURSOR")]
    after_cursor: Option<String>,

    /// Maximum number of request retention rows to return.
    #[arg(long, value_name = "COUNT", default_value_t = 50)]
    limit: u16,
}

#[derive(Debug, Args)]
struct RequestRetentionExactArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Compiled change-request entity identifier.
    #[arg(long, value_name = "ENTITY")]
    request_entity: String,

    /// Exact request record UUID.
    #[arg(long, value_name = "UUID")]
    request_id: String,

    /// Exact proposal version to inspect or erase.
    #[arg(long, value_name = "VERSION")]
    proposal_version: i64,
}

#[derive(Debug, Args)]
struct WebhookSampleArgs {
    /// Registry Server authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Stable authored event identifier.
    #[arg(long, value_name = "ID")]
    event: String,
}

#[derive(Debug, Args)]
struct WebhookListArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Maximum number of value-free delivery rows to return.
    #[arg(long, value_name = "COUNT", default_value_t = 50)]
    limit: u16,
}

#[derive(Debug, Args)]
struct WebhookReplayArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Stable event UUID shown by `webhook list`.
    #[arg(long, value_name = "UUID")]
    event_id: String,

    /// Compiled delivery identifier shown by `webhook list`.
    #[arg(long, value_name = "ID")]
    delivery_id: String,

    /// Current generation shown by `webhook list`.
    #[arg(long, value_name = "NUMBER")]
    expected_generation: i64,
}

#[derive(Debug, Subcommand)]
enum DataCommand {
    /// Validate a JSONL import file against one closed package plan.
    Validate(DataValidateArgs),
    /// Import JSONL records through the ordinary authenticated batch API.
    Import(DataImportArgs),
    /// Export records through the ordinary authenticated list API.
    Export(DataExportArgs),
}

#[derive(Debug, Args)]
struct DataValidateArgs {
    /// Absolute closed package directory used only for deterministic planning.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Compiled entity identifier.
    #[arg(long, value_name = "ID")]
    entity: String,

    /// Compiled non-anonymous access profile identifier.
    #[arg(long, value_name = "ID")]
    profile: String,

    /// Import item operation.
    #[arg(long, value_enum)]
    operation: DataOperationArg,

    /// JSON Lines import file.
    #[arg(long, value_name = "FILE")]
    input: PathBuf,
}

#[derive(Debug, Args)]
struct DataImportArgs {
    /// Absolute closed package directory used only for deterministic planning.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Registry Server base URL. HTTP is accepted only for loopback hosts.
    #[arg(long, value_name = "URL")]
    server_url: String,

    /// File containing one bearer access token and no other credential material.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    access_token_file: PathBuf,

    /// Compiled entity identifier.
    #[arg(long, value_name = "ID")]
    entity: String,

    /// Compiled non-anonymous access profile identifier.
    #[arg(long, value_name = "ID")]
    profile: String,

    /// Import item operation.
    #[arg(long, value_enum)]
    operation: DataOperationArg,

    /// JSON Lines import file.
    #[arg(long, value_name = "FILE")]
    input: PathBuf,

    /// Import checkpoint file. A ctl-held .state sidecar is created beside it.
    #[arg(long, value_name = "FILE")]
    checkpoint: PathBuf,

    /// Stop after this many committed chunks, for resumable operator runs.
    #[arg(long, value_name = "COUNT")]
    max_chunks: Option<u64>,
}

#[derive(Debug, Args)]
struct DataExportArgs {
    /// Absolute closed package directory used only for deterministic planning.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Registry Server base URL. HTTP is accepted only for loopback hosts.
    #[arg(long, value_name = "URL")]
    server_url: String,

    /// File containing one bearer access token and no other credential material.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    access_token_file: PathBuf,

    /// Compiled entity identifier.
    #[arg(long, value_name = "ID")]
    entity: String,

    /// Compiled non-anonymous export-enabled access profile identifier.
    #[arg(long, value_name = "ID")]
    profile: String,

    /// Requested readable field. Repeat for every exported field.
    #[arg(long = "field", value_name = "ID", required = true)]
    fields: Vec<String>,

    /// New JSON Lines output file.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,

    /// New export checkpoint file written after every page.
    #[arg(long, value_name = "FILE")]
    checkpoint: PathBuf,

    /// Stop after this many pages, for bounded operator runs.
    #[arg(long, value_name = "COUNT")]
    max_pages: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum DataOperationArg {
    Create,
    Patch,
}

impl From<DataOperationArg> for registry_server::data::DataImportOperation {
    fn from(value: DataOperationArg) -> Self {
        match value {
            DataOperationArg::Create => Self::Create,
            DataOperationArg::Patch => Self::Patch,
        }
    }
}

#[derive(Debug, Subcommand)]
enum MigrationCommand {
    /// Explain the verified package's closed migration plan without executing it.
    Explain(MigrationExplainArgs),

    /// Assess a Registry pinned by a failed activation, and execute only the safe transition it names.
    Reconcile(MigrationReconcileArgs),
}

#[derive(Debug, Subcommand)]
enum HistoryCommand {
    /// Erase retained history for one record using an owner-only JSON request file.
    Erase(HistoryEraseArgs),

    /// Restore snapshot coverage from the current state using an owner-only JSON request file.
    Rebaseline(HistoryRebaselineArgs),
}

#[derive(Debug, Args)]
struct MigrationExplainArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct MigrationReconcileArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute directory of the verified package the failed activation pinned.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Operator change reference recorded as a keyed hash beside an executed transition.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: String,

    /// Perform the single safe transition the assessment names.
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Args)]
struct HistoryEraseArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute owner-only JSON erasure request file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    request_file: PathBuf,
}

#[derive(Debug, Args)]
struct HistoryRebaselineArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute owner-only JSON rebaseline request file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    request_file: PathBuf,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("baseline")
        .required(true)
        .multiple(false)
        .args(["runtime_config", "package"])
))]
struct DiffArgs {
    /// Registry Server authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Absolute runtime configuration whose package bindings and trust apply.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: Option<PathBuf>,

    /// Closed package inspected for integrity only, without activation authority.
    #[arg(long, value_name = "DIRECTORY")]
    package: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ArtifactSelector {
    Openapi,
    Schemas,
    Actions,
    Manifest,
    Metadata,
    Sql,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum ExplainSubject {
    Model,
    Access,
    Routes,
    Queries,
    Actions,
    ChangeRequests,
    Events,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProfileArg {
    #[default]
    Authoring,
    Production,
}

impl From<ProfileArg> for CompileProfile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Authoring => Self::Authoring,
            ProfileArg::Production => Self::Production,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactReport {
    path: String,
    media_type: String,
    sha256: String,
    byte_length: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    revision: String,
    findings: Vec<ToolDiagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<ArtifactReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<Value>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestSuccessReport {
    ok: bool,
    command: &'static str,
    compiled_revision: String,
    request_entity: String,
    planner: PlannerTestIdentityReport,
    disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_reason: Option<PlannerTestQueueReasonReport>,
    effects: Vec<PlannerTestEffectReport>,
    counts: PlannerTestCountReport,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestIdentityReport {
    kind: &'static str,
    abi: String,
    script_sha256: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestQueueReasonReport {
    code: String,
    label: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestEffectReport {
    id: String,
    target_kind: &'static str,
    operation: &'static str,
    fields: Vec<String>,
    depends_on: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestCountReport {
    effects: usize,
    field_mutations: usize,
    dependencies: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureReport {
    ok: bool,
    command: &'static str,
    diagnostics: Vec<ToolDiagnostic>,
}

/// CLI-owned diagnostic envelope. Shared compiler diagnostics are converted at
/// the command boundary so machine consumers receive one stable shape without
/// widening the compiler's public diagnostic contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolDiagnostic {
    severity: DiagnosticSeverity,
    code: String,
    artifact: DiagnosticArtifact,
    path: String,
    message: String,
    suggested_action: SuggestedAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticArtifact {
    CommandArguments,
    RegistryProject,
    ProjectInitialization,
    GeneratedArtifacts,
    CompiledInventory,
    RuntimeConfiguration,
    BaselinePackage,
    CompiledDiff,
    PackageBuild,
    PackageSigningInput,
    SchemaTestReceipt,
    SchemaTestCandidate,
    FixtureJourneys,
    SchemaTestCredentials,
    SchemaTestDatabase,
    SchemaTestExecution,
    SchemaTestOutput,
    PackageSignatures,
    PackageActivation,
    DatabaseMigration,
    StartupDependencies,
    VerifiedPackage,
    DataOperation,
    DataCheckpoint,
    DataTransport,
    WebhookSample,
    WebhookOperations,
    RequestRetentionOperation,
    HistoryErasure,
    HistoryRebaseline,
    PlannerTest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SuggestedAction {
    CorrectCommandUsage,
    CorrectAuthoringSource,
    ReviewAuthoringFinding,
    ChooseSafeOutputDirectory,
    SelectAvailableArtifact,
    RetryArtifactGeneration,
    RetryInventoryExplanation,
    UpdateModuleLocks,
    CorrectRuntimeConfiguration,
    VerifyPackagePath,
    VerifyPackagePermissions,
    VerifyPackageTrust,
    VerifyPackageBinding,
    VerifyPackageIntegrity,
    ReviewCompiledDiff,
    CorrectPackageBuild,
    ReviewSigningInput,
    SupplySchemaTestReceipt,
    CorrectSchemaTestCandidate,
    CorrectFixtureJourneys,
    SupplySchemaTestCredentials,
    PrepareSchemaTestDatabase,
    RecreateDisposableDatabase,
    ChooseSchemaTestOutput,
    SupplyExternalSignatures,
    VerifyMigrationAuthority,
    ReconcileFailedMigration,
    RestorePreActivationBackup,
    ResolveActiveRequestProposals,
    VerifyStartupDependencies,
    CorrectDataBinding,
    CorrectDataInput,
    VerifyDataCheckpoint,
    VerifyDataTransport,
    SelectWebhookEvent,
    VerifyWebhookOperation,
    VerifyRequestRetentionOperation,
    PrepareHistoryErasureRequest,
    PrepareHistoryRebaselineRequest,
    ReviewRetainedHistory,
    CorrectPlannerTestInput,
}

#[derive(Serialize)]
struct DoctorSuccessReport {
    ok: bool,
    command: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifySuccessReport {
    ok: bool,
    command: &'static str,
    assurance: BaselineAssurance,
    package_revision: String,
    registry: VerifiedRegistryReport,
    inventory: VerifiedInventoryReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationExplainSuccessReport {
    ok: bool,
    command: &'static str,
    assurance: BaselineAssurance,
    package_revision: String,
    plan: MigrationInspectionSummary,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationReconcileSuccessReport {
    ok: bool,
    command: &'static str,
    assurance: BaselineAssurance,
    #[serde(flatten)]
    outcome: ReconcileLifecycleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryEraseSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: HistoryErasureLifecycleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRebaselineSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: HistoryRebaselineLifecycleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PackageSuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    state: PackageReportState,
    package_revision: String,
    signature_threshold: u16,
    provided_signatures: usize,
    package_files: usize,
    signing_input: ArtifactReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaTestSuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    package_revision: String,
    schema_fingerprint: String,
    signing_input_sha256: String,
    successful_journey_ids: Vec<String>,
    receipt: ArtifactReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PackageReportState {
    AwaitingSignatures,
    Published,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplySuccessReport {
    ok: bool,
    command: &'static str,
    activation: ApplyActivation,
    package_revision: String,
    schema_fingerprint: String,
    package_sequence: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataValidateSuccessReport {
    ok: bool,
    command: &'static str,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    profile_id: String,
    operation: DataOperationArg,
    input_length: u64,
    item_count: u64,
    chunk_count: usize,
    maximum_items: u16,
    maximum_bytes: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataImportSuccessReport {
    ok: bool,
    command: &'static str,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    profile_id: String,
    operation: DataOperationArg,
    input_length: u64,
    item_count: u64,
    completed_chunk_count: u64,
    committed_items: u64,
    complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataExportSuccessReport {
    ok: bool,
    command: &'static str,
    package_revision: String,
    schema_fingerprint: String,
    entity_id: String,
    profile_id: String,
    requested_fields: Vec<String>,
    completed_page_count: u64,
    record_count: u64,
    output_length: u64,
    complete: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookSampleSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: WebhookSampleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookListSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: WebhookListOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebhookReplaySuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: WebhookReplayOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestRetentionListSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: RequestRetentionListOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestRetentionDryRunSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: RequestRetentionDryRunOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestRetentionEraseSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: RequestRetentionEraseOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApplyActivation {
    Initial,
    Successor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedRegistryReport {
    id: String,
    version: String,
    revision: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedInventoryReport {
    modules: usize,
    entities: usize,
    routes: usize,
    access_entries: usize,
    queries: usize,
    event_deliveries: usize,
    ddl_statements: usize,
    generated_artifacts: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BaselineAssurance {
    RuntimeBound,
    IntegrityOnly,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiffSuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    baseline_assurance: BaselineAssurance,
    findings: Vec<ToolDiagnostic>,
    #[serde(flatten)]
    diff: CompiledRegistryDiff,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMigrateSuccessReport {
    ok: bool,
    command: &'static str,
    changed: bool,
    written: bool,
    dataset_id: String,
    proposed_authority_id: String,
    proposed_public_service_id: String,
    diff: String,
}

#[derive(Debug)]
struct CapturedProjectSource {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    project_assets: Vec<CapturedModuleAssetSource>,
    modules: Vec<CapturedModuleSource>,
}

#[derive(Debug)]
struct CapturedModuleSource {
    id: String,
    module: RegistryModule,
    bytes: Vec<u8>,
    assets: Vec<CapturedModuleAssetSource>,
}

#[derive(Debug)]
struct CapturedModuleAssetSource {
    path: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct CapturedPackageCandidate {
    compiled: CompiledRegistry,
    environment: String,
    instance_id: String,
    database_id: String,
    sequence: u64,
    compiler_source_revision: String,
    prior_revision: Option<String>,
    signature_policy: SignaturePolicy,
    project: PackageSourceFile,
    project_assets: Vec<PackageSourceFile>,
    modules: Vec<PackageModuleSource>,
    fixture_journeys: PackageSourceFile,
    migration_plan: PackageMigrationPlanInput,
    prevalidation_schema_fingerprint: Option<String>,
}

impl CapturedPackageCandidate {
    fn registry(&self) -> &CompiledRegistry {
        &self.compiled
    }

    fn fixture_journeys(&self) -> &[u8] {
        &self.fixture_journeys.bytes
    }

    fn validate_runtime_binding(
        &self,
        config: &registry_server::runtime_config::RuntimeConfig,
    ) -> Result<(), TestLifecycleError> {
        for (path, matches) in [
            (
                "runtimeConfig.identity.environment",
                config.identity().environment() == self.environment,
            ),
            (
                "runtimeConfig.identity.instanceId",
                config.identity().instance_id() == self.instance_id,
            ),
            (
                "runtimeConfig.identity.databaseId",
                config.identity().database_id() == self.database_id,
            ),
            (
                "runtimeConfig.package.compilerSourceRevision",
                config.package().compiler_source_revision() == self.compiler_source_revision,
            ),
        ] {
            if !matches {
                return Err(TestLifecycleError::CandidateBinding { path });
            }
        }
        Ok(())
    }

    fn prevalidate(&self) -> Result<(), PackageError> {
        const PLACEHOLDER_SCHEMA_FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        self.clone()
            .prepare(
                self.prevalidation_schema_fingerprint
                    .as_deref()
                    .unwrap_or(PLACEHOLDER_SCHEMA_FINGERPRINT)
                    .to_owned(),
            )
            .map(|_| ())
    }

    fn prepare(self, schema_fingerprint: String) -> Result<PreparedPackage, PackageError> {
        registry_server::package::prepare_package_with_project_assets(
            PackageBuildRequest {
                environment: self.environment,
                instance_id: self.instance_id,
                database_id: self.database_id,
                sequence: self.sequence,
                prior_revision: self.prior_revision,
                compiler_source_revision: self.compiler_source_revision,
                schema_fingerprint,
                signature_policy: self.signature_policy,
                project: self.project,
                modules: self.modules,
                fixture_journeys: self.fixture_journeys,
                migration_plan: self.migration_plan,
            },
            self.project_assets,
        )
    }
}

/// Return the public command tree without running a project operation.
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    command
}

/// Parse the current process arguments and execute the selected operation.
pub fn main_entry() -> ExitCode {
    run_from(std::env::args_os(), &mut io::stdout(), &mut io::stderr())
}

/// Run from explicit arguments. This is public so process-level tests can use
/// the exact command parser while keeping filesystem behavior in one place.
pub fn run_from<I, T>(arguments: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
    let machine_mode = requested_json(&arguments);
    let cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                let _ = write!(stdout, "{error}");
                return ExitCode::SUCCESS;
            }
            if !machine_mode {
                // The parser already names the unknown flag or the missing
                // argument, so an adopter reads clap's own rendering.
                let _ = write!(stderr, "{error}");
                return ExitCode::from(USAGE_EXIT);
            }
            let report = FailureReport {
                ok: false,
                command: "usage",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("usage.invalid", "arguments", &unstyled_usage(&error)),
                    DiagnosticArtifact::CommandArguments,
                    SuggestedAction::CorrectCommandUsage,
                )],
            };
            let _ = write_failure(&report, OutputFormat::Json, stdout, stderr);
            return ExitCode::from(USAGE_EXIT);
        }
    };

    let format = cli.format;
    let result = match cli.command {
        Command::Init(args) => init(&args.destination),
        Command::Check(args) => check(&args.project, profile(args.production)).and_then(|report| {
            if args.deny_findings && !report.findings.is_empty() {
                Err(FailureReport {
                    ok: false,
                    command: "check",
                    diagnostics: report.findings,
                })
            } else {
                Ok(report)
            }
        }),
        Command::Project(args) => match args.command {
            ProjectCommand::Lock(args) => project_lock(&args.project, args.check),
            ProjectCommand::Migrate(args) => {
                return match project_migrate(&args.project, args.write) {
                    Ok(report) => write_project_migrate_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
            ProjectCommand::PlannerTest(args) => {
                return match planner_test(&args) {
                    Ok(report) => write_planner_test_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
        },
        Command::Generate(args) => generate(
            args.artifact,
            &args.project,
            profile(args.production),
            &args.output,
        ),
        Command::Explain(args) => explain(
            args.subject,
            &args.project,
            profile(args.production),
            args.scenario.as_deref(),
        ),
        Command::Diff(args) => {
            return match diff(&args) {
                Ok(report) => write_diff_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Package(args) => {
            return match package(&args) {
                Ok(report) => write_package_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Test(args) => {
            return match test(&args) {
                Ok(report) => write_schema_test_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Apply(args) => {
            return match apply(&args) {
                Ok(report) => write_apply_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Doctor(args) => {
            return match doctor::run(&args.runtime_config) {
                Ok(()) => write_doctor_success(format, stdout, stderr),
                Err(diagnostic) => {
                    let (artifact, action) =
                        if diagnostic.code.starts_with("startup.runtime_config") {
                            (
                                DiagnosticArtifact::RuntimeConfiguration,
                                SuggestedAction::CorrectRuntimeConfiguration,
                            )
                        } else {
                            (
                                DiagnosticArtifact::StartupDependencies,
                                SuggestedAction::VerifyStartupDependencies,
                            )
                        };
                    write_failure(
                        &FailureReport {
                            ok: false,
                            command: "doctor",
                            diagnostics: vec![tool_diagnostic(diagnostic, artifact, action)],
                        },
                        format,
                        stdout,
                        stderr,
                    )
                }
            };
        }
        Command::Verify(args) => {
            return match verify(&args) {
                Ok(report) => write_verify_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Migration(args) => match args.command {
            MigrationCommand::Explain(args) => {
                return match migration_explain(&args) {
                    Ok(report) => write_migration_explain_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
            MigrationCommand::Reconcile(args) => {
                return match migration_reconcile(&args) {
                    Ok(report) => {
                        write_migration_reconcile_success(&report, format, stdout, stderr)
                    }
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
        },
        Command::History(args) => match args.command {
            HistoryCommand::Erase(args) => {
                return match history_erase(&args) {
                    Ok(report) => write_history_erase_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
            HistoryCommand::Rebaseline(args) => {
                return match history_rebaseline(&args) {
                    Ok(report) => write_history_rebaseline_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
        },
        Command::Data(args) => match args.command {
            DataCommand::Validate(args) => {
                return match data_validate(&args) {
                    Ok(report) => write_data_validate_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
            DataCommand::Import(args) => {
                return match data_import(&args) {
                    Ok(report) => write_data_import_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
            DataCommand::Export(args) => {
                return match data_export(&args) {
                    Ok(report) => write_data_export_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
        },
        Command::Webhook(args) => {
            return match args.command {
                WebhookCommand::Sample(args) => match webhook_sample(&args) {
                    Ok(report) => write_webhook_sample_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
                WebhookCommand::List(args) => match webhook_list(&args) {
                    Ok(report) => write_webhook_list_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
                WebhookCommand::Replay(args) => match webhook_replay(&args) {
                    Ok(report) => write_webhook_replay_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
            };
        }
        Command::RequestRetention(args) => {
            return match args.command {
                RequestRetentionCommand::List(args) => match request_retention_list(&args) {
                    Ok(report) => {
                        write_request_retention_list_success(&report, format, stdout, stderr)
                    }
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
                RequestRetentionCommand::DryRun(args) => match request_retention_dry_run(&args) {
                    Ok(report) => {
                        write_request_retention_dry_run_success(&report, format, stdout, stderr)
                    }
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
                RequestRetentionCommand::Erase(args) => match request_retention_erase(&args) {
                    Ok(report) => {
                        write_request_retention_erase_success(&report, format, stdout, stderr)
                    }
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
            };
        }
    };

    match result {
        Ok(report) => write_success(&report, format, stdout, stderr),
        Err(failure) => write_failure(&failure, format, stdout, stderr),
    }
}

fn request_retention_list(
    args: &RequestRetentionListArgs,
) -> Result<RequestRetentionListSuccessReport, FailureReport> {
    let outcome = request_retention::list(
        &args.runtime_config,
        args.request_entity.as_deref(),
        args.after_cursor.as_deref(),
        args.limit,
    )
    .map_err(|error| request_retention_failure("request-retention list", error))?;
    Ok(RequestRetentionListSuccessReport {
        ok: true,
        command: "request-retention list",
        outcome,
    })
}

fn request_retention_dry_run(
    args: &RequestRetentionExactArgs,
) -> Result<RequestRetentionDryRunSuccessReport, FailureReport> {
    let outcome = request_retention::dry_run(
        &args.runtime_config,
        &args.request_entity,
        &args.request_id,
        args.proposal_version,
    )
    .map_err(|error| request_retention_failure("request-retention dry-run", error))?;
    Ok(RequestRetentionDryRunSuccessReport {
        ok: true,
        command: "request-retention dry-run",
        outcome,
    })
}

fn request_retention_erase(
    args: &RequestRetentionExactArgs,
) -> Result<RequestRetentionEraseSuccessReport, FailureReport> {
    let outcome = request_retention::erase(
        &args.runtime_config,
        &args.request_entity,
        &args.request_id,
        args.proposal_version,
    )
    .map_err(|error| request_retention_failure("request-retention erase", error))?;
    Ok(RequestRetentionEraseSuccessReport {
        ok: true,
        command: "request-retention erase",
        outcome,
    })
}

fn request_retention_failure(
    command: &'static str,
    error: RequestRetentionCliError,
) -> FailureReport {
    let (code, message) = match error {
        RequestRetentionCliError::Operator => (
            "request_retention.operation.refused",
            "the request retention operation was refused",
        ),
        RequestRetentionCliError::ActiveDetailPinned => (
            "request_retention.detail.pinned",
            "active request detail is still pinned",
        ),
        RequestRetentionCliError::RetainMode => (
            "request_retention.mode.retain",
            "the request retention policy does not permit operator erasure",
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, "requestRetention", message),
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
        )],
    }
}

fn history_erase(args: &HistoryEraseArgs) -> Result<HistoryEraseSuccessReport, FailureReport> {
    let outcome = history_erasure_lifecycle::run(HistoryErasureLifecycleRequest {
        runtime_config: &args.runtime_config,
        request_file: &args.request_file,
    })
    .map_err(history_erasure_lifecycle_failure)?;
    Ok(HistoryEraseSuccessReport {
        ok: true,
        command: "history erase",
        outcome,
    })
}

fn history_erasure_lifecycle_failure(error: HistoryErasureLifecycleError) -> FailureReport {
    let error = match error {
        HistoryErasureLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("history erase", "history.erase", error);
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        HistoryErasureLifecycleError::RuntimeConfigPath => (
            "history.erase.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        HistoryErasureLifecycleError::RequestFile => (
            "history.erase.request_file.refused",
            "requestFile",
            "the history erasure request file must be absolute, owner-only, and bounded",
            DiagnosticArtifact::HistoryErasure,
            SuggestedAction::PrepareHistoryErasureRequest,
        ),
        HistoryErasureLifecycleError::RequestDocument | HistoryErasureLifecycleError::Target => (
            "history.erase.request.refused",
            "requestFile",
            "the history erasure request document was refused",
            DiagnosticArtifact::HistoryErasure,
            SuggestedAction::PrepareHistoryErasureRequest,
        ),
        HistoryErasureLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        HistoryErasureLifecycleError::Package(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Signature => SuggestedAction::VerifyPackageTrust,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "history.erase.package.refused",
                "package",
                "the active runtime package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        HistoryErasureLifecycleError::DatabaseConfiguration
        | HistoryErasureLifecycleError::TimeoutConfiguration => (
            "history.erase.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryErasureLifecycleError::Runtime => (
            "history.erase.runtime.unavailable",
            "runtime",
            "the history erasure runtime is unavailable",
            DiagnosticArtifact::HistoryErasure,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryErasureLifecycleError::Erasure(error) => match error {
            registry_server::history_erasure::HistoryErasureError::InvalidInput
            | registry_server::history_erasure::HistoryErasureError::TargetUnavailable => (
                "history.erase.target.refused",
                "requestFile",
                "the requested history erasure target was refused",
                DiagnosticArtifact::HistoryErasure,
                SuggestedAction::PrepareHistoryErasureRequest,
            ),
            registry_server::history_erasure::HistoryErasureError::MigrationAuthority => (
                "history.erase.migration_authority.refused",
                "database",
                "history erasure requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_server::history_erasure::HistoryErasureError::HistoryNotReady
            | registry_server::history_erasure::HistoryErasureError::Unavailable => (
                "history.erase.unavailable",
                "history",
                "history erasure storage is unavailable",
                DiagnosticArtifact::HistoryErasure,
                SuggestedAction::VerifyMigrationAuthority,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "history erase",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn history_rebaseline(
    args: &HistoryRebaselineArgs,
) -> Result<HistoryRebaselineSuccessReport, FailureReport> {
    let outcome = history_rebaseline_lifecycle::run(HistoryRebaselineLifecycleRequest {
        runtime_config: &args.runtime_config,
        request_file: &args.request_file,
    })
    .map_err(history_rebaseline_lifecycle_failure)?;
    Ok(HistoryRebaselineSuccessReport {
        ok: true,
        command: "history rebaseline",
        outcome,
    })
}

fn history_rebaseline_lifecycle_failure(error: HistoryRebaselineLifecycleError) -> FailureReport {
    let error = match error {
        HistoryRebaselineLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("history rebaseline", "history.rebaseline", error);
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        HistoryRebaselineLifecycleError::RuntimeConfigPath => (
            "history.rebaseline.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        HistoryRebaselineLifecycleError::RequestFile => (
            "history.rebaseline.request_file.refused",
            "requestFile",
            "the history rebaseline request file must be absolute, owner-only, and bounded",
            DiagnosticArtifact::HistoryRebaseline,
            SuggestedAction::PrepareHistoryRebaselineRequest,
        ),
        HistoryRebaselineLifecycleError::RequestDocument => (
            "history.rebaseline.request.refused",
            "requestFile",
            "the history rebaseline request document was refused",
            DiagnosticArtifact::HistoryRebaseline,
            SuggestedAction::PrepareHistoryRebaselineRequest,
        ),
        HistoryRebaselineLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        HistoryRebaselineLifecycleError::Package(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Signature => SuggestedAction::VerifyPackageTrust,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "history.rebaseline.package.refused",
                "package",
                "the active runtime package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        HistoryRebaselineLifecycleError::DatabaseConfiguration
        | HistoryRebaselineLifecycleError::TimeoutConfiguration => (
            "history.rebaseline.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryRebaselineLifecycleError::Runtime => (
            "history.rebaseline.runtime.unavailable",
            "runtime",
            "the history rebaseline runtime is unavailable",
            DiagnosticArtifact::HistoryRebaseline,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryRebaselineLifecycleError::Rebaseline(error) => match error {
            registry_server::history_rebaseline::HistoryRebaselineError::InvalidInput => (
                "history.rebaseline.request.refused",
                "requestFile",
                "the history rebaseline request document was refused",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::PrepareHistoryRebaselineRequest,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::MigrationAuthority => (
                "history.rebaseline.migration_authority.refused",
                "database",
                "history rebaseline requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::CoverageComplete => (
                "history.rebaseline.coverage.complete",
                "history",
                "snapshot coverage is already complete, so there is nothing to rebaseline",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::PrepareHistoryRebaselineRequest,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::UnindexedRevisions => (
                "history.rebaseline.revisions.unindexed",
                "history",
                "history rebaseline requires every retained journal head to be indexed by a commit",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::ReviewRetainedHistory,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::LiveHistoryMismatch => (
                "history.rebaseline.live_rows.unverified",
                "history",
                "history rebaseline requires the retained journal head to reproduce every live row; \
                 the first record that disagrees is not named, so compare the live rows with their \
                 revisions to find it",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::ReviewRetainedHistory,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::LiveRowBudgetExceeded => (
                "history.rebaseline.live_rows.budget_exceeded",
                "history",
                "history rebaseline verifies at most 1000 live rows in one transaction and this \
                 registry holds more, so retrying cannot restore snapshot coverage",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::ReviewRetainedHistory,
            ),
            registry_server::history_rebaseline::HistoryRebaselineError::HistoryNotReady
            | registry_server::history_rebaseline::HistoryRebaselineError::Unavailable => (
                "history.rebaseline.unavailable",
                "history",
                "history rebaseline storage is unavailable",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::VerifyMigrationAuthority,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "history rebaseline",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn webhook_sample(args: &WebhookSampleArgs) -> Result<WebhookSampleSuccessReport, FailureReport> {
    let compiled = compile(&args.project, ProfileArg::Authoring, "webhook sample")?;
    let outcome =
        webhook_lifecycle::sample(&compiled, &args.event).map_err(|error| match error {
            WebhookLifecycleError::Event => unavailable_webhook_event(&compiled),
            error => webhook_lifecycle_failure("webhook sample", error),
        })?;
    Ok(WebhookSampleSuccessReport {
        ok: true,
        command: "webhook sample",
        outcome,
    })
}

fn webhook_list(args: &WebhookListArgs) -> Result<WebhookListSuccessReport, FailureReport> {
    let outcome = webhook_lifecycle::list(&args.runtime_config, args.limit)
        .map_err(|error| webhook_lifecycle_failure("webhook list", error))?;
    Ok(WebhookListSuccessReport {
        ok: true,
        command: "webhook list",
        outcome,
    })
}

fn webhook_replay(args: &WebhookReplayArgs) -> Result<WebhookReplaySuccessReport, FailureReport> {
    let outcome = webhook_lifecycle::replay(
        &args.runtime_config,
        &args.event_id,
        &args.delivery_id,
        args.expected_generation,
    )
    .map_err(|error| webhook_lifecycle_failure("webhook replay", error))?;
    Ok(WebhookReplaySuccessReport {
        ok: true,
        command: "webhook replay",
        outcome,
    })
}

/// Name the authored event ids this project delivers, so an adopter selects one
/// without reading the project again. The selection an adopter typed is not
/// rendered back.
fn unavailable_webhook_event(compiled: &CompiledRegistry) -> FailureReport {
    let mut authored: Vec<&str> = compiled
        .event_deliveries()
        .deliveries
        .iter()
        .map(|delivery| delivery.event_id.as_str())
        .collect();
    authored.sort_unstable();
    authored.dedup();
    let message = if authored.is_empty() {
        "this project authors no webhook delivery, so there is no event to sample".to_owned()
    } else {
        format!(
            "the selected webhook event is unavailable; this project delivers: {}",
            authored.join(", ")
        )
    };
    FailureReport {
        ok: false,
        command: "webhook sample",
        diagnostics: vec![tool_diagnostic(
            diagnostic("webhook.sample.event_refused", "event", &message),
            DiagnosticArtifact::WebhookSample,
            SuggestedAction::SelectWebhookEvent,
        )],
    }
}

fn webhook_lifecycle_failure(command: &'static str, error: WebhookLifecycleError) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        WebhookLifecycleError::Event => (
            "webhook.sample.event_refused",
            "event",
            "the selected webhook event is unavailable",
            DiagnosticArtifact::WebhookSample,
            SuggestedAction::SelectWebhookEvent,
        ),
        WebhookLifecycleError::Sample => (
            "webhook.sample.render_refused",
            "sample",
            "the webhook sample could not be rendered",
            DiagnosticArtifact::WebhookSample,
            SuggestedAction::SelectWebhookEvent,
        ),
        WebhookLifecycleError::Operator => (
            "webhook.operation.refused",
            "webhook",
            "the webhook operation was refused",
            DiagnosticArtifact::WebhookOperations,
            SuggestedAction::VerifyWebhookOperation,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn data_validate(args: &DataValidateArgs) -> Result<DataValidateSuccessReport, FailureReport> {
    let outcome = data_lifecycle::validate_import(DataValidateRequest {
        package: &args.package,
        entity: &args.entity,
        operation: args.operation.into(),
        profile: &args.profile,
        input: &args.input,
    })
    .map_err(|error| data_lifecycle_failure("data validate", "data.validate", error))?;
    Ok(DataValidateSuccessReport {
        ok: true,
        command: "data validate",
        package_revision: outcome.package_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        entity_id: outcome.entity_id,
        profile_id: outcome.profile_id,
        operation: operation_arg(outcome.operation),
        input_length: outcome.input_length,
        item_count: outcome.item_count,
        chunk_count: outcome.chunk_count,
        maximum_items: outcome.maximum_items,
        maximum_bytes: outcome.maximum_bytes,
    })
}

fn data_import(args: &DataImportArgs) -> Result<DataImportSuccessReport, FailureReport> {
    let outcome = data_lifecycle::run_import(DataImportRequest {
        package: &args.package,
        server_url: &args.server_url,
        access_token_file: &args.access_token_file,
        entity: &args.entity,
        operation: args.operation.into(),
        profile: &args.profile,
        input: &args.input,
        checkpoint: &args.checkpoint,
        max_chunks: args.max_chunks,
    })
    .map_err(|error| data_lifecycle_failure("data import", "data.import", error))?;
    Ok(DataImportSuccessReport {
        ok: true,
        command: "data import",
        package_revision: outcome.package_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        entity_id: outcome.entity_id,
        profile_id: outcome.profile_id,
        operation: operation_arg(outcome.operation),
        input_length: outcome.input_length,
        item_count: outcome.item_count,
        completed_chunk_count: outcome.completed_chunk_count,
        committed_items: outcome.committed_items,
        complete: outcome.complete,
    })
}

fn data_export(args: &DataExportArgs) -> Result<DataExportSuccessReport, FailureReport> {
    let outcome = data_lifecycle::run_export(DataExportRequest {
        package: &args.package,
        server_url: &args.server_url,
        access_token_file: &args.access_token_file,
        entity: &args.entity,
        profile: &args.profile,
        fields: &args.fields,
        output: &args.output,
        checkpoint: &args.checkpoint,
        max_pages: args.max_pages,
    })
    .map_err(|error| data_lifecycle_failure("data export", "data.export", error))?;
    Ok(DataExportSuccessReport {
        ok: true,
        command: "data export",
        package_revision: outcome.package_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        entity_id: outcome.entity_id,
        profile_id: outcome.profile_id,
        requested_fields: outcome.requested_fields,
        completed_page_count: outcome.completed_page_count,
        record_count: outcome.record_count,
        output_length: outcome.output_length,
        complete: outcome.complete,
    })
}

fn operation_arg(operation: registry_server::data::DataImportOperation) -> DataOperationArg {
    match operation {
        registry_server::data::DataImportOperation::Create => DataOperationArg::Create,
        registry_server::data::DataImportOperation::Patch => DataOperationArg::Patch,
    }
}

fn data_lifecycle_failure(
    command: &'static str,
    prefix: &'static str,
    error: DataLifecycleError,
) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        DataLifecycleError::PackagePath => (
            format!("{prefix}.package.path_invalid"),
            "package",
            "the package path must be absolute",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackagePath,
        ),
        DataLifecycleError::Package(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Signature => SuggestedAction::VerifyPackageTrust,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                format!("{prefix}.package.refused"),
                "package",
                "the data package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        DataLifecycleError::PackageManifest => (
            format!("{prefix}.package.refused"),
            "package",
            "the data package was refused",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackageIntegrity,
        ),
        DataLifecycleError::Input | DataLifecycleError::Data(DataError::InvalidInput) => (
            format!("{prefix}.input.refused"),
            "input",
            "the data input was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataInput,
        ),
        DataLifecycleError::Data(DataError::InvalidItem)
        | DataLifecycleError::Data(DataError::ItemTooLarge) => (
            format!("{prefix}.item.refused"),
            "input",
            "a data item was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataInput,
        ),
        DataLifecycleError::Data(DataError::InvalidBinding) => (
            format!("{prefix}.binding.refused"),
            "data",
            "the data operation binding was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataBinding,
        ),
        DataLifecycleError::Checkpoint
        | DataLifecycleError::Data(DataError::CheckpointMismatch) => (
            format!("{prefix}.checkpoint.refused"),
            "checkpoint",
            "the data checkpoint was refused",
            DiagnosticArtifact::DataCheckpoint,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::Output => (
            format!("{prefix}.output.refused"),
            "output",
            "the data output was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataInput,
        ),
        DataLifecycleError::ServerUrl => (
            format!("{prefix}.server_url.refused"),
            "serverUrl",
            "the Registry Server URL was refused",
            DiagnosticArtifact::DataTransport,
            SuggestedAction::VerifyDataTransport,
        ),
        DataLifecycleError::Token => (
            format!("{prefix}.access_token.refused"),
            "accessToken",
            "the access token file was refused",
            DiagnosticArtifact::DataTransport,
            SuggestedAction::VerifyDataTransport,
        ),
        DataLifecycleError::Runtime | DataLifecycleError::Transport => (
            format!("{prefix}.transport.unavailable"),
            "transport",
            "the Registry data transport is unavailable",
            DiagnosticArtifact::DataTransport,
            SuggestedAction::VerifyDataTransport,
        ),
        DataLifecycleError::Data(DataError::OperationRefused) => (
            format!("{prefix}.operation.refused"),
            "data",
            "the Registry data operation was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataBinding,
        ),
        DataLifecycleError::Data(DataError::InvalidResponse) => (
            format!("{prefix}.response.refused"),
            "data",
            "the Registry data response was refused",
            DiagnosticArtifact::DataTransport,
            SuggestedAction::VerifyDataTransport,
        ),
        DataLifecycleError::Data(DataError::TransportUnavailable) => (
            format!("{prefix}.transport.unavailable"),
            "transport",
            "the Registry data transport is unavailable",
            DiagnosticArtifact::DataTransport,
            SuggestedAction::VerifyDataTransport,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(&code, path, message),
            artifact,
            action,
        )],
    }
}

fn diff(args: &DiffArgs) -> Result<DiffSuccessReport, FailureReport> {
    let candidate = compile(&args.project, ProfileArg::Authoring, "diff")?;
    let (baseline, baseline_assurance) = match (&args.runtime_config, &args.package) {
        (Some(runtime_path), None) => {
            let inspected = inspect_runtime_package(runtime_path).map_err(|error| match error {
                RuntimePackageInspectionError::RuntimeConfigPath => diff_failure(
                    "diff.runtime_config.path_invalid",
                    "runtimeConfig",
                    "the runtime configuration path must be absolute",
                ),
                RuntimePackageInspectionError::RuntimeConfig(error) => {
                    runtime_config_diff_failure(error)
                }
                RuntimePackageInspectionError::Package(error) => package_diff_failure(error),
            })?;
            (inspected, BaselineAssurance::RuntimeBound)
        }
        (None, Some(package_root)) => (
            inspect_package_integrity(package_root).map_err(package_diff_failure)?,
            BaselineAssurance::IntegrityOnly,
        ),
        _ => unreachable!("clap enforces exactly one diff baseline selector"),
    };
    let compiled_diff =
        classify_registry_diff(baseline.registry(), &candidate, baseline.package_revision());
    let mut compiler_findings = candidate.findings().to_vec();
    compiler_findings.extend(unsupported_diff_findings(&compiled_diff));
    compiler_findings.sort();
    compiler_findings.dedup();
    let findings = compiler_findings
        .into_iter()
        .map(|diagnostic| {
            let (artifact, action) = if diagnostic.code == "diff.classification.unsupported" {
                (
                    DiagnosticArtifact::CompiledDiff,
                    SuggestedAction::ReviewCompiledDiff,
                )
            } else {
                (
                    DiagnosticArtifact::RegistryProject,
                    SuggestedAction::ReviewAuthoringFinding,
                )
            };
            tool_diagnostic(diagnostic, artifact, action)
        })
        .collect();
    Ok(DiffSuccessReport {
        ok: true,
        command: "diff",
        profile: ProfileArg::Authoring,
        baseline_assurance,
        findings,
        diff: compiled_diff,
    })
}

fn package(args: &PackageArgs) -> Result<PackageSuccessReport, FailureReport> {
    // The receipt names the fingerprint its rehearsal reached, so an operator who
    // does not restate it still packages against that exact managed catalogue.
    let schema_fingerprint = match &args.schema_fingerprint {
        Some(supplied) => supplied.clone(),
        None => package_lifecycle::receipt_schema_fingerprint(&args.test_receipt)
            .map_err(package_lifecycle_failure)?,
    };
    let prepared = prepare_candidate(&args.candidate, schema_fingerprint, "package")?;
    let receipt = package_lifecycle::validate_test_receipt(
        &args.test_receipt,
        &prepared,
        args.schema_fingerprint.as_deref(),
    )
    .map_err(package_lifecycle_failure)?;
    let outcome =
        package_lifecycle::run(prepared, receipt, &args.output, args.signatures.as_deref())
            .map_err(package_lifecycle_failure)?;
    Ok(PackageSuccessReport {
        ok: true,
        command: "package",
        profile: ProfileArg::Production,
        state: match outcome.state {
            PackageLifecycleState::AwaitingSignatures => PackageReportState::AwaitingSignatures,
            PackageLifecycleState::Published => PackageReportState::Published,
        },
        package_revision: outcome.package_revision,
        signature_threshold: outcome.signature_threshold,
        provided_signatures: outcome.provided_signatures,
        package_files: outcome.package_files,
        signing_input: ArtifactReport {
            path: "signing-input.json".to_owned(),
            media_type: "application/json".to_owned(),
            sha256: outcome.signing_input_sha256,
            byte_length: outcome.signing_input_bytes,
        },
    })
}

fn test(args: &TestArgs) -> Result<SchemaTestSuccessReport, FailureReport> {
    let output = test_lifecycle::preflight_output(&args.output).map_err(test_lifecycle_failure)?;
    let candidate = capture_candidate(&args.candidate, "test")?;
    let outcome = test_lifecycle::run(TestLifecycleRequest {
        candidate,
        runtime_config: &args.runtime_config,
        credentials: &args.credentials,
        output,
    })
    .map_err(test_lifecycle_failure)?;
    Ok(SchemaTestSuccessReport {
        ok: true,
        command: "test",
        profile: ProfileArg::Production,
        package_revision: outcome.package_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        signing_input_sha256: outcome.signing_input_sha256,
        successful_journey_ids: outcome.successful_journey_ids,
        receipt: ArtifactReport {
            path: test_lifecycle::receipt_artifact_path().to_owned(),
            media_type: "application/json".to_owned(),
            sha256: outcome.receipt_sha256,
            byte_length: outcome.receipt_bytes,
        },
    })
}

fn prepare_candidate(
    args: &PackageCandidateArgs,
    schema_fingerprint: String,
    command: &'static str,
) -> Result<PreparedPackage, FailureReport> {
    capture_candidate(args, command)?
        .prepare(schema_fingerprint)
        .map_err(|error| candidate_package_error(command, error))
}

fn capture_candidate(
    args: &PackageCandidateArgs,
    command: &'static str,
) -> Result<CapturedPackageCandidate, FailureReport> {
    let source = capture_project_source(&args.project).map_err(|diagnostic| {
        source_failure(
            command,
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let compiled = compile_captured_project(&source, ProfileArg::Production, command)?;
    let identity = compiled.package().ok_or_else(|| {
        candidate_failure(
            command,
            "package.identity.refused",
            "package",
            "the production package identity was refused",
            candidate_artifact(command),
            SuggestedAction::CorrectPackageBuild,
        )
    })?;
    let environment = identity.environment.clone();
    let instance_id = identity.instance_id.clone();
    let sequence = identity.sequence;
    let compiler_source_revision = identity.source_revision.clone();
    let project_bytes = source.project_bytes;
    let project_assets = source
        .project_assets
        .into_iter()
        .map(|asset| PackageSourceFile {
            path: asset.path,
            bytes: asset.bytes,
        })
        .collect();
    let modules = source
        .modules
        .into_iter()
        .map(|module| PackageModuleSource {
            path: format!("source/modules/{}/module.yaml", module.id),
            id: module.id,
            bytes: module.bytes,
            assets: module
                .assets
                .into_iter()
                .map(|asset| PackageSourceFile {
                    path: asset.path,
                    bytes: asset.bytes,
                })
                .collect(),
        })
        .collect();
    let fixture_journey_bytes = read_bounded_source_file(
        &args.project.join(FIXTURE_JOURNEYS_PATH),
        "source.fixture_journeys.missing",
        FIXTURE_JOURNEYS_PATH,
        MAX_PACKAGE_SOURCE_FILE_BYTES,
    )
    .map_err(|diagnostic| FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )],
    })?;
    let mut prevalidation_schema_fingerprint = None;
    let mut reviewed_changes = String::new();
    let (prior_revision, migration_plan) = match args.baseline_runtime_config.as_deref() {
        Some(runtime_config) => {
            let baseline = inspect_runtime_predecessor_package(runtime_config)
                .map_err(|error| inspection_failure(command, "package.baseline", error))?;
            if baseline.environment() != environment
                || baseline.instance_id() != instance_id
                || baseline.database_id() != args.database_id
            {
                return Err(candidate_failure(
                    command,
                    "package.baseline.identity",
                    "baselineRuntimeConfig",
                    "the verified predecessor package identity does not match the candidate package and database binding",
                    DiagnosticArtifact::RuntimeConfiguration,
                    SuggestedAction::CorrectRuntimeConfiguration,
                ));
            }
            let changes = registry_server::package::compiled_registry_change_set_from_baseline(
                baseline.migration_baseline(),
                &compiled,
                baseline.package_revision(),
            );
            let unsupported = rendered_changes(&changes.changes, |change| {
                change.class == CompiledRegistryChangeClass::Unsupported
            });
            if !unsupported.is_empty() {
                return Err(candidate_failure(
                    command,
                    "migration.change.unsupported",
                    "candidate",
                    &format!(
                        "the migration planner does not support these successor changes: {unsupported}. Inspect diff and revise the candidate. Reviewed artifacts cannot authorize unsupported changes"
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::CorrectPackageBuild,
                ));
            }
            let reviewable = rendered_changes(&changes.changes, |change| {
                change.class != CompiledRegistryChangeClass::CompatibleAdditive
            });
            let plan = if let Some(directory) = &args.reviewed_migrations {
                let review = reviewed_migrations::capture(directory).map_err(|diagnostic| {
                    source_failure(
                        command,
                        diagnostic,
                        DiagnosticArtifact::DatabaseMigration,
                        SuggestedAction::CorrectPackageBuild,
                    )
                })?;
                prevalidation_schema_fingerprint = Some(review.declared_schema_fingerprint);
                reviewed_changes = reviewable;
                PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
                    prior_baseline: Box::new(baseline.migration_baseline().clone()),
                    prior_schema_fingerprint: baseline.schema_fingerprint().to_owned(),
                    migrations: review.sources,
                }
            } else {
                if registry_server::package::change_set_to_applicable_migration_plan(&changes)
                    .is_err()
                {
                    return Err(candidate_failure(
                        command,
                        "migration.review.required",
                        "reviewedMigrations",
                        &format!(
                            "the successor cannot be applied automatically; the changes to review are: {reviewable}. Run diff, review the migration and its rehearsal evidence, then provide --reviewed-migrations to both test and package"
                        ),
                        DiagnosticArtifact::DatabaseMigration,
                        SuggestedAction::CorrectPackageBuild,
                    ));
                }
                PackageMigrationPlanInput::SuccessorFromBaseline {
                    prior_baseline: Box::new(baseline.migration_baseline().clone()),
                }
            };
            (Some(baseline.package_revision().to_owned()), plan)
        }
        None => (None, PackageMigrationPlanInput::InitialCompiledDdl),
    };
    let mut signature_key_ids = args.signature_key_ids.clone();
    signature_key_ids.sort();
    if signature_key_ids.windows(2).any(|ids| ids[0] == ids[1]) {
        return Err(candidate_failure(
            command,
            "package.signature_policy.refused",
            "signaturePolicy",
            "the package signature policy was refused",
            candidate_artifact(command),
            SuggestedAction::CorrectPackageBuild,
        ));
    }
    let candidate = CapturedPackageCandidate {
        compiled,
        environment,
        instance_id,
        database_id: args.database_id.clone(),
        sequence,
        prior_revision,
        compiler_source_revision,
        signature_policy: SignaturePolicy {
            threshold: args.signature_threshold,
            key_ids: signature_key_ids,
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        project_assets,
        modules,
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: fixture_journey_bytes,
        },
        migration_plan,
        prevalidation_schema_fingerprint,
    };
    if args.reviewed_migrations.is_some() {
        candidate.prevalidate().map_err(|_| {
            candidate_failure(
                command,
                "migration.review.refused",
                "reviewedMigrations",
                &format!(
                    "the reviewed plan was refused; it has to cover exactly these changes: {reviewed_changes}. Check change coverage, canonical JSON, artifact hashes, prior package and schema bindings, and target fingerprint. Use the same reviewed directory for test and package"
                ),
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::CorrectPackageBuild,
            )
        })?;
    }
    Ok(candidate)
}

fn apply(args: &ApplyArgs) -> Result<ApplySuccessReport, FailureReport> {
    let outcome = apply_lifecycle::run(ApplyLifecycleRequest {
        runtime_config: &args.runtime_config,
        package: &args.package,
        initial: args.initial,
        backups: &args.backups,
    })
    .map_err(apply_lifecycle_failure)?;
    Ok(ApplySuccessReport {
        ok: true,
        command: "apply",
        activation: if outcome.initial {
            ApplyActivation::Initial
        } else {
            ApplyActivation::Successor
        },
        package_revision: outcome.package_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        package_sequence: outcome.package_sequence,
    })
}

fn package_lifecycle_failure(error: PackageLifecycleError) -> FailureReport {
    match error {
        PackageLifecycleError::Package(error) => {
            let (code, action) = match error {
                PackageError::Signature => (
                    "package.signatures.refused",
                    SuggestedAction::SupplyExternalSignatures,
                ),
                PackageError::UnsafePath | PackageError::Permissions => (
                    "package.output.refused",
                    SuggestedAction::CorrectPackageBuild,
                ),
                _ => (
                    "package.build.refused",
                    SuggestedAction::CorrectPackageBuild,
                ),
            };
            package_failure(
                code,
                "package",
                "the package build was refused",
                DiagnosticArtifact::PackageBuild,
                action,
            )
        }
        PackageLifecycleError::Output => package_failure(
            "package.output.refused",
            "output",
            "the package output was refused",
            DiagnosticArtifact::PackageSigningInput,
            SuggestedAction::ReviewSigningInput,
        ),
        PackageLifecycleError::SignatureDocument => package_failure(
            "package.signatures.refused",
            "signatures",
            "the external package signatures were refused",
            DiagnosticArtifact::PackageSignatures,
            SuggestedAction::SupplyExternalSignatures,
        ),
        PackageLifecycleError::TestReceiptMissing => package_failure(
            "package.test_receipt.missing",
            "testReceipt",
            "the schema-test receipt is required",
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptRefused { message } => package_failure(
            "package.test_receipt.refused",
            "testReceipt",
            &message,
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptInvalid { message } => package_failure(
            "package.test_receipt.invalid",
            "testReceipt",
            &message,
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptFingerprint { receipt, supplied } => package_failure(
            "package.test_receipt.fingerprint_mismatch",
            "testReceipt.targetManagedSchemaFingerprint",
            &format!(
                "--schema-fingerprint is {supplied} but the schema-test receipt was produced for {receipt}"
            ),
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptIdentity {
            field,
            receipt,
            package,
        } => package_failure(
            "package.test_receipt.identity_mismatch",
            &format!("testReceipt.{field}"),
            &format!(
                "the schema-test receipt records {field} {receipt} but this candidate declares {package}"
            ),
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptCandidate {
            field,
            receipt,
            package,
        } => package_failure(
            "package.test_receipt.candidate_mismatch",
            &format!("testReceipt.{field}"),
            &format!(
                "the schema-test receipt records {field} {receipt} but this candidate builds {package}; run test again for this candidate"
            ),
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
        PackageLifecycleError::TestReceiptEvidence { message } => package_failure(
            "package.test_receipt.evidence_mismatch",
            "testReceipt",
            &message,
            DiagnosticArtifact::SchemaTestReceipt,
            SuggestedAction::SupplySchemaTestReceipt,
        ),
    }
}

fn test_lifecycle_failure(error: TestLifecycleError) -> FailureReport {
    let error = match error {
        TestLifecycleError::CandidateBinding { path } => {
            return candidate_failure(
                "test",
                "test.candidate.refused",
                path,
                "the runtime identity must match the project package identity and the --database-id selection",
                DiagnosticArtifact::SchemaTestCandidate,
                SuggestedAction::CorrectSchemaTestCandidate,
            );
        }
        TestLifecycleError::JourneyStep { path, message } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("test.step.failed", &path, &message),
                    DiagnosticArtifact::FixtureJourneys,
                    SuggestedAction::CorrectFixtureJourneys,
                )],
            };
        }
        TestLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("test", "test", error);
        }
        TestLifecycleError::JourneySyntax { path, message } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("test.journeys.refused", &path, message),
                    DiagnosticArtifact::FixtureJourneys,
                    SuggestedAction::CorrectFixtureJourneys,
                )],
            };
        }
        TestLifecycleError::Journeys { message } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic(
                        "test.journeys.refused",
                        FIXTURE_JOURNEYS_PATH,
                        &format!("the packaged schema-test journey suite was refused: {message}"),
                    ),
                    DiagnosticArtifact::FixtureJourneys,
                    SuggestedAction::CorrectFixtureJourneys,
                )],
            };
        }
        TestLifecycleError::Credentials { path, message } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("test.credentials.refused", &path, &message),
                    DiagnosticArtifact::SchemaTestCredentials,
                    SuggestedAction::SupplySchemaTestCredentials,
                )],
            };
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        TestLifecycleError::RuntimeConfigPath => (
            "test.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        TestLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        TestLifecycleError::JourneySyntax { .. } => unreachable!("handled before match"),
        TestLifecycleError::Journeys { .. } => unreachable!("handled before match"),
        TestLifecycleError::Credentials { .. } => unreachable!("handled before match"),
        TestLifecycleError::JourneyStep { .. } => unreachable!("handled before match"),
        TestLifecycleError::CandidateBinding { .. } => unreachable!("handled before match"),
        TestLifecycleError::Candidate => (
            "test.candidate.refused",
            "candidate",
            "the schema-test package candidate was refused",
            DiagnosticArtifact::SchemaTestCandidate,
            SuggestedAction::CorrectSchemaTestCandidate,
        ),
        TestLifecycleError::ReviewFingerprint => (
            "migration.review.fingerprint_mismatch",
            "reviewedMigrations",
            "the reviewed target fingerprint does not match the schema measured on the disposable database; rehearse the exact candidate and correct the review evidence before retrying",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::CorrectPackageBuild,
        ),
        TestLifecycleError::Database => (
            "test.database.unavailable",
            "database",
            "the schema-test database is unavailable; recreate the disposable database before retrying",
            DiagnosticArtifact::SchemaTestDatabase,
            SuggestedAction::RecreateDisposableDatabase,
        ),
        TestLifecycleError::Execution => (
            "test.execution.refused",
            "execution",
            "the schema-test execution was refused; recreate the disposable database before retrying",
            DiagnosticArtifact::SchemaTestExecution,
            SuggestedAction::RecreateDisposableDatabase,
        ),
        TestLifecycleError::OutputPreflight => (
            "test.output.refused",
            "output",
            "the schema-test receipt output was refused",
            DiagnosticArtifact::SchemaTestOutput,
            SuggestedAction::ChooseSchemaTestOutput,
        ),
        TestLifecycleError::OutputCommit => (
            "test.output.failed",
            "output",
            "the schema-test receipt could not be published; recreate the disposable database before retrying",
            DiagnosticArtifact::SchemaTestOutput,
            SuggestedAction::RecreateDisposableDatabase,
        ),
        TestLifecycleError::Runtime => (
            "test.runtime.unavailable",
            "runtime",
            "the schema-test runtime is unavailable",
            DiagnosticArtifact::SchemaTestExecution,
            SuggestedAction::PrepareSchemaTestDatabase,
        ),
    };
    FailureReport {
        ok: false,
        command: "test",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn apply_lifecycle_failure(error: ApplyLifecycleError) -> FailureReport {
    let error = match error {
        ApplyLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("apply", "apply", error);
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        ApplyLifecycleError::RuntimeConfigPath => (
            "apply.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        ApplyLifecycleError::TargetPackagePath => (
            "apply.package.path_invalid",
            "package",
            "the target package path must be absolute",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackagePath,
        ),
        ApplyLifecycleError::CurrentPackage(error) | ApplyLifecycleError::TargetPackage(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Signature => SuggestedAction::VerifyPackageTrust,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "apply.package.refused",
                "package",
                "the activation package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        ApplyLifecycleError::EventDestinations => (
            "apply.event_destinations.refused",
            "eventDestinations",
            "the event destination bindings were refused",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::DatabaseConfiguration | ApplyLifecycleError::TimeoutConfiguration => (
            "apply.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::BackupArgument => (
            "apply.backup_evidence.refused",
            "backup",
            "the destructive backup evidence argument was refused",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::CorrectPackageBuild,
        ),
        ApplyLifecycleError::Runtime => (
            "apply.runtime.unavailable",
            "runtime",
            "the package apply runtime is unavailable",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::Apply(error) => match error {
            registry_server::migration::MigrationError::PackageBinding
            | registry_server::migration::MigrationError::EmptyPlan => (
                "apply.package.refused",
                "package",
                "the activation package was refused",
                DiagnosticArtifact::VerifiedPackage,
                SuggestedAction::VerifyPackageBinding,
            ),
            registry_server::migration::MigrationError::BackupEvidence => (
                "apply.backup_evidence.refused",
                "backup",
                "the destructive backup evidence was refused",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::CorrectPackageBuild,
            ),
            registry_server::migration::MigrationError::ApplyFailed => (
                "apply.migration.failed",
                "database",
                "the Registry package apply failed and requires exact-target reconciliation",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::ReconcileFailedMigration,
            ),
            registry_server::migration::MigrationError::ActiveRequestProposals => (
                "apply.request_proposals.active",
                "changeRequest",
                "active request proposals require explicit rebase or cancellation before activating changed request contracts",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::ResolveActiveRequestProposals,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "apply",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn package_failure(
    code: &str,
    path: &str,
    message: &str,
    artifact: DiagnosticArtifact,
    action: SuggestedAction,
) -> FailureReport {
    FailureReport {
        ok: false,
        command: "package",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn candidate_package_error(command: &'static str, error: PackageError) -> FailureReport {
    if command == "package" {
        return package_lifecycle_failure(PackageLifecycleError::Package(error));
    }
    candidate_failure(
        command,
        "test.candidate.refused",
        "candidate",
        "the schema-test package candidate was refused",
        DiagnosticArtifact::SchemaTestCandidate,
        match error {
            PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
            PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
            PackageError::Signature => SuggestedAction::VerifyPackageTrust,
            PackageError::Binding => SuggestedAction::VerifyPackageBinding,
            _ => SuggestedAction::CorrectSchemaTestCandidate,
        },
    )
}

fn candidate_failure(
    command: &'static str,
    code: &str,
    path: &str,
    message: &str,
    artifact: DiagnosticArtifact,
    action: SuggestedAction,
) -> FailureReport {
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn candidate_artifact(command: &'static str) -> DiagnosticArtifact {
    if command == "test" {
        DiagnosticArtifact::SchemaTestCandidate
    } else {
        DiagnosticArtifact::PackageBuild
    }
}

fn verify(args: &VerifyArgs) -> Result<VerifySuccessReport, FailureReport> {
    let inspected = inspect_runtime_package(&args.runtime_config)
        .map_err(|error| inspection_failure("verify", "verify", error))?;
    let registry = inspected.registry();
    Ok(VerifySuccessReport {
        ok: true,
        command: "verify",
        assurance: BaselineAssurance::RuntimeBound,
        package_revision: inspected.package_revision().to_owned(),
        registry: VerifiedRegistryReport {
            id: registry.registry_id().to_owned(),
            version: registry.version().to_owned(),
            revision: registry.revision().to_owned(),
        },
        inventory: VerifiedInventoryReport {
            modules: registry.module_closure().len(),
            entities: registry.entities().len(),
            routes: registry.routes().routes.len(),
            access_entries: registry.access().entries.len(),
            queries: registry.queries().operations.len(),
            event_deliveries: registry.event_deliveries().deliveries.len(),
            ddl_statements: registry.ddl().statements.len(),
            generated_artifacts: registry.artifacts().entries().len(),
        },
    })
}

fn migration_explain(
    args: &MigrationExplainArgs,
) -> Result<MigrationExplainSuccessReport, FailureReport> {
    let inspected = inspect_runtime_package(&args.runtime_config)
        .map_err(|error| inspection_failure("migration explain", "migration.explain", error))?;
    Ok(MigrationExplainSuccessReport {
        ok: true,
        command: "migration explain",
        assurance: BaselineAssurance::RuntimeBound,
        package_revision: inspected.package_revision().to_owned(),
        plan: inspected.migration_summary().clone(),
    })
}

fn migration_reconcile(
    args: &MigrationReconcileArgs,
) -> Result<MigrationReconcileSuccessReport, FailureReport> {
    let outcome = reconcile_lifecycle::run(ReconcileLifecycleRequest {
        runtime_config: &args.runtime_config,
        package: &args.package,
        operator_reference: &args.operator_reference,
        execute: args.execute,
    })
    .map_err(reconcile_lifecycle_failure)?;
    Ok(MigrationReconcileSuccessReport {
        ok: true,
        command: "migration reconcile",
        assurance: BaselineAssurance::RuntimeBound,
        outcome,
    })
}

fn reconcile_lifecycle_failure(error: ReconcileLifecycleError) -> FailureReport {
    let error = match error {
        ReconcileLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("migration reconcile", "migration.reconcile", error);
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        ReconcileLifecycleError::RuntimeConfigPath => (
            "migration.reconcile.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ReconcileLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        ReconcileLifecycleError::TargetPackagePath => (
            "migration.reconcile.package.path_invalid",
            "package",
            "the pinned target package path must be absolute",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackagePath,
        ),
        ReconcileLifecycleError::OperatorReference => (
            "migration.reconcile.operator_reference.refused",
            "operatorReference",
            "the operator reference must be present, bounded, and free of control characters",
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        ),
        ReconcileLifecycleError::ActivePackage(error)
        | ReconcileLifecycleError::TargetPackage(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Signature => SuggestedAction::VerifyPackageTrust,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "migration.reconcile.package.refused",
                "package",
                "the reconciled activation package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        ReconcileLifecycleError::DatabaseConfiguration
        | ReconcileLifecycleError::TimeoutConfiguration => (
            "migration.reconcile.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ReconcileLifecycleError::Runtime => (
            "migration.reconcile.runtime.unavailable",
            "runtime",
            "the migration reconciliation runtime is unavailable",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ReconcileLifecycleError::Reconcile(error) => match error {
            ReconcileError::InvalidInput => (
                "migration.reconcile.request.refused",
                "runtimeConfig",
                "the reconciliation requires a keyed audit profile and a bound active package",
                DiagnosticArtifact::RuntimeConfiguration,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            ReconcileError::MigrationAuthority => (
                "migration.reconcile.migration_authority.refused",
                "database",
                "migration reconciliation requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            ReconcileError::PackageBinding => (
                "migration.reconcile.package.refused",
                "package",
                "the presented package is not a verified successor of the active package",
                DiagnosticArtifact::VerifiedPackage,
                SuggestedAction::VerifyPackageBinding,
            ),
            ReconcileError::NotExecutable(outcome) => match outcome {
                ReconcileOutcome::Ready => (
                    "migration.reconcile.outcome.ready",
                    "database",
                    "no failed activation is pinned, so there is no transition to execute",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::CorrectCommandUsage,
                ),
                ReconcileOutcome::InProgress => (
                    "migration.reconcile.outcome.in_progress",
                    "database",
                    "another session holds the exclusive migration lock; reconcile once it releases",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReconcileFailedMigration,
                ),
                // Completable and Revertible are the outcomes an execution
                // performs, so a refusal only ever names an unresolved one.
                ReconcileOutcome::Unresolvable
                | ReconcileOutcome::Completable
                | ReconcileOutcome::Revertible => (
                    "migration.reconcile.outcome.unresolvable",
                    "database",
                    "neither completing nor abandoning the pinned target is provably safe",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::RestorePreActivationBackup,
                ),
            },
            ReconcileError::Unavailable => (
                "migration.reconcile.unavailable",
                "database",
                "the Registry migration state is unavailable",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "migration reconcile",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn inspection_failure(
    command: &'static str,
    prefix: &'static str,
    error: RuntimePackageInspectionError,
) -> FailureReport {
    if let RuntimePackageInspectionError::RuntimeConfig(error) = error {
        return runtime_config_failure(command, prefix, error);
    }
    let (code, path, message, artifact, action) = match error {
        RuntimePackageInspectionError::RuntimeConfigPath => (
            format!("{prefix}.runtime_config.path_invalid"),
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        RuntimePackageInspectionError::RuntimeConfig(_) => unreachable!("handled before match"),
        RuntimePackageInspectionError::Package(error) => {
            let (suffix, action) = match error {
                PackageError::UnsafePath => ("path_refused", SuggestedAction::VerifyPackagePath),
                PackageError::Permissions => (
                    "permissions_refused",
                    SuggestedAction::VerifyPackagePermissions,
                ),
                PackageError::Signature => {
                    ("signature_refused", SuggestedAction::VerifyPackageTrust)
                }
                PackageError::Binding => ("binding_refused", SuggestedAction::VerifyPackageBinding),
                PackageError::Closure
                | PackageError::Integrity
                | PackageError::CanonicalJson
                | PackageError::Derivation
                | PackageError::MigrationPlan => {
                    ("integrity_refused", SuggestedAction::VerifyPackageIntegrity)
                }
                PackageError::Bounds | PackageError::Read => {
                    ("package_refused", SuggestedAction::VerifyPackageIntegrity)
                }
            };
            (
                format!("{prefix}.package.{suffix}"),
                "package",
                "the configured package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(&code, path, message),
            artifact,
            action,
        )],
    }
}

fn runtime_config_diff_failure(error: RuntimeConfigError) -> FailureReport {
    let detail = runtime_config_diagnostic("diff", error);
    diff_failure(&detail.code, detail.path, &detail.message)
}

struct RuntimeConfigDiagnostic {
    code: String,
    path: &'static str,
    message: String,
}

fn runtime_config_diagnostic(prefix: &str, error: RuntimeConfigError) -> RuntimeConfigDiagnostic {
    let metadata = error.metadata();
    RuntimeConfigDiagnostic {
        code: format!("{prefix}.{}", metadata.code()),
        path: metadata.path(),
        message: error.to_string(),
    }
}

fn runtime_config_failure(
    command: &'static str,
    prefix: &str,
    error: RuntimeConfigError,
) -> FailureReport {
    let detail = runtime_config_diagnostic(prefix, error);
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(&detail.code, detail.path, &detail.message),
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        )],
    }
}

fn package_diff_failure(error: PackageError) -> FailureReport {
    let (code, action) = match error {
        PackageError::UnsafePath => (
            "diff.baseline.path_refused",
            SuggestedAction::VerifyPackagePath,
        ),
        PackageError::Permissions => (
            "diff.baseline.permissions_refused",
            SuggestedAction::VerifyPackagePermissions,
        ),
        PackageError::Signature => (
            "diff.baseline.signature_refused",
            SuggestedAction::VerifyPackageTrust,
        ),
        PackageError::Binding => (
            "diff.baseline.binding_refused",
            SuggestedAction::VerifyPackageBinding,
        ),
        PackageError::Closure
        | PackageError::Integrity
        | PackageError::CanonicalJson
        | PackageError::Derivation
        | PackageError::MigrationPlan => (
            "diff.baseline.integrity_refused",
            SuggestedAction::VerifyPackageIntegrity,
        ),
        PackageError::Bounds | PackageError::Read => (
            "diff.baseline.package_refused",
            SuggestedAction::VerifyPackageIntegrity,
        ),
    };
    diff_failure_with_action(
        code,
        "baseline",
        "the baseline package was refused",
        DiagnosticArtifact::BaselinePackage,
        action,
    )
}

fn diff_failure(code: &str, path: &str, message: &str) -> FailureReport {
    diff_failure_with_action(
        code,
        path,
        message,
        DiagnosticArtifact::RuntimeConfiguration,
        SuggestedAction::CorrectRuntimeConfiguration,
    )
}

fn diff_failure_with_action(
    code: &str,
    path: &str,
    message: &str,
    artifact: DiagnosticArtifact,
    action: SuggestedAction,
) -> FailureReport {
    FailureReport {
        ok: false,
        command: "diff",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn unsupported_diff_findings(diff: &CompiledRegistryDiff) -> Vec<Diagnostic> {
    diff.changes
        .iter()
        .filter(|change| change.classification == DiffClassification::Unsupported)
        .map(|change| Diagnostic {
            severity: DiagnosticSeverity::Finding,
            code: "diff.classification.unsupported".to_owned(),
            path: diff_change_path(&change.change),
            message: "the compiled change cannot be classified more precisely".to_owned(),
        })
        .collect()
}

/// List the selected changes as `code at target`, with the sentence a code
/// carries beyond its name, so a refusal names what an adopter has to act on.
fn rendered_changes(
    changes: &[registry_server::package::CompiledRegistryChange],
    selected: impl Fn(&registry_server::package::CompiledRegistryChange) -> bool,
) -> String {
    let mut rendered: Vec<String> = changes
        .iter()
        .filter(|change| selected(change))
        .map(|change| {
            let target = match (
                change.target.entity_id.as_deref(),
                change.target.member_id.as_deref(),
            ) {
                (Some(entity), Some(member)) => format!("{entity}.{member}"),
                (Some(entity), None) => entity.to_owned(),
                (None, _) => "registry".to_owned(),
            };
            let mut line = format!("{} at {target}", change_code_name(change.code));
            if let Some(explanation) = change.code.explanation() {
                line.push_str(" (");
                line.push_str(explanation);
                line.push(')');
            }
            line
        })
        .collect();
    rendered.sort();
    rendered.dedup();
    rendered.join("; ")
}

fn change_code_name(code: registry_server::package::CompiledRegistryChangeCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

fn diff_change_path(change: &registry_server::package::CompiledRegistryChange) -> String {
    match (
        change.target.entity_id.as_deref(),
        change.target.member_id.as_deref(),
    ) {
        (Some(entity), Some(member)) => format!("changes.{entity}.{member}"),
        (Some(entity), None) => format!("changes.{entity}"),
        (None, _) => "changes.registry".to_owned(),
    }
}

fn requested_json(arguments: &[OsString]) -> bool {
    arguments.iter().enumerate().any(|(index, argument)| {
        argument == "--format=json"
            || (argument == "--format"
                && arguments.get(index + 1).is_some_and(|next| next == "json"))
    })
}

/// Render a parser error as plain text so a machine-readable diagnostic carries
/// the argument the parser named without terminal styling.
fn unstyled_usage(error: &clap::Error) -> String {
    let rendered = error.render().to_string();
    let rendered = rendered.trim();
    rendered
        .strip_prefix("error: ")
        .unwrap_or(rendered)
        .to_owned()
}

fn profile(production: bool) -> ProfileArg {
    if production {
        ProfileArg::Production
    } else {
        ProfileArg::Authoring
    }
}

fn init(destination: &Path) -> Result<SuccessReport, FailureReport> {
    let files = init_files();
    write_source_files(destination, &files).map_err(|diagnostic| FailureReport {
        ok: false,
        command: "init",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::ProjectInitialization,
            SuggestedAction::ChooseSafeOutputDirectory,
        )],
    })?;
    let compiled = compile(destination, ProfileArg::Authoring, "init")?;
    Ok(SuccessReport {
        ok: true,
        command: "init",
        profile: ProfileArg::Authoring,
        revision: compiled.revision().to_owned(),
        findings: compiler_findings(&compiled),
        artifacts: files
            .iter()
            .map(|(path, bytes)| artifact_report(path, init_media_type(path), bytes))
            .collect(),
        explanation: None,
    })
}

fn check(project_path: &Path, profile: ProfileArg) -> Result<SuccessReport, FailureReport> {
    let compiled = compile(project_path, profile, "check")?;
    Ok(SuccessReport {
        ok: true,
        command: "check",
        profile,
        revision: compiled.revision().to_owned(),
        findings: compiler_findings(&compiled),
        artifacts: Vec::new(),
        explanation: None,
    })
}

fn project_migrate(
    project_path: &Path,
    write: bool,
) -> Result<ProjectMigrateSuccessReport, FailureReport> {
    validate_project_directory(project_path).map_err(|diagnostic| {
        source_failure(
            "project migrate",
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let registry_path = project_path.join("registry.yaml");
    let original = read_bounded_source_file(
        &registry_path,
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )
    .map_err(|diagnostic| {
        source_failure(
            "project migrate",
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;

    if let Ok(project) = parse_project_yaml(&original) {
        let projection = project.manifest_projection.ok_or_else(|| FailureReport {
            ok: false,
            command: "project migrate",
            diagnostics: vec![tool_diagnostic(
                diagnostic(
                    "project.migrate.projection_missing",
                    "project.manifestProjection",
                    "the project has no singular Manifest projection to migrate",
                ),
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::CorrectAuthoringSource,
            )],
        })?;
        let dataset = projection.datasets.first().ok_or_else(|| FailureReport {
            ok: false,
            command: "project migrate",
            diagnostics: vec![tool_diagnostic(
                diagnostic(
                    "project.migrate.datasets_empty",
                    "project.manifestProjection.datasets",
                    "the plural project has no dataset; add at least one datasets[] entry",
                ),
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::CorrectAuthoringSource,
            )],
        })?;
        return Ok(ProjectMigrateSuccessReport {
            ok: true,
            command: "project migrate",
            changed: false,
            written: false,
            dataset_id: dataset.id.clone(),
            proposed_authority_id: projection.catalog.publisher.id,
            proposed_public_service_id: projection.public_service.id,
            diff: String::new(),
        });
    }

    let mut migrated =
        project_migration::migrate_registry_yaml(&original).map_err(|diagnostic| {
            source_failure(
                "project migrate",
                diagnostic,
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::CorrectAuthoringSource,
            )
        })?;
    let mut files = BTreeMap::new();
    files.insert(
        "registry.yaml".to_owned(),
        (original.clone(), migrated.bytes.clone()),
    );
    let mut module_locks = Vec::new();
    for (module_id, bytes) in discover_module_files(project_path).map_err(|diagnostic| {
        source_failure(
            "project migrate",
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })? {
        let updated = project_migration::add_module_entity_membership(&bytes, &migrated.dataset_id)
            .map_err(|diagnostic| {
                source_failure(
                    "project migrate",
                    diagnostic,
                    DiagnosticArtifact::RegistryProject,
                    SuggestedAction::CorrectAuthoringSource,
                )
            })?
            .unwrap_or_else(|| bytes.clone());
        let module = parse_module_yaml(&updated).map_err(|failure| FailureReport {
            ok: false,
            command: "project migrate",
            diagnostics: failure
                .diagnostics()
                .iter()
                .cloned()
                .map(|diagnostic| {
                    tool_diagnostic(
                        diagnostic,
                        DiagnosticArtifact::RegistryProject,
                        SuggestedAction::CorrectAuthoringSource,
                    )
                })
                .collect(),
        })?;
        let assets = load_module_asset_files(project_path, &module_id, &module)
            .map_err(|diagnostic| {
                source_failure(
                    "project migrate",
                    diagnostic,
                    DiagnosticArtifact::RegistryProject,
                    SuggestedAction::CorrectAuthoringSource,
                )
            })?
            .into_iter()
            .map(|asset| ModuleAssetSource {
                module: Some(module_id.clone()),
                path: asset.path,
                bytes: asset.bytes,
            })
            .collect::<Vec<_>>();
        module_locks.push(ModuleLockSource {
            id: module.id.clone(),
            version: module.version.clone(),
            digest: Some(module_digest_with_assets(&module, &assets)),
        });
        if updated != bytes {
            files.insert(format!("modules/{module_id}/module.yaml"), (bytes, updated));
        }
    }
    module_locks.sort_by(|left, right| left.id.cmp(&right.id));
    if !module_locks.is_empty() {
        migrated.bytes = project_migration::update_module_locks(&migrated.bytes, &module_locks)
            .map_err(|diagnostic| {
                source_failure(
                    "project migrate",
                    diagnostic,
                    DiagnosticArtifact::RegistryProject,
                    SuggestedAction::CorrectAuthoringSource,
                )
            })?;
        files
            .get_mut("registry.yaml")
            .expect("registry diff exists")
            .1 = migrated.bytes.clone();
    }
    let diff = project_migration::review_diff(&files);
    if write {
        write_migration_files(project_path, &files).map_err(|diagnostic| {
            source_failure(
                "project migrate",
                diagnostic,
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::CorrectAuthoringSource,
            )
        })?;
    }
    Ok(ProjectMigrateSuccessReport {
        ok: true,
        command: "project migrate",
        changed: true,
        written: write,
        dataset_id: migrated.dataset_id,
        proposed_authority_id: migrated.authority_id,
        proposed_public_service_id: migrated.public_service_id,
        diff,
    })
}

fn project_lock(project_path: &Path, check_only: bool) -> Result<SuccessReport, FailureReport> {
    let mut source = capture_project_source_for_lock(project_path).map_err(|diagnostic| {
        source_failure(
            "project lock",
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    let current_locks = source
        .project
        .modules
        .iter()
        .map(|lock| (lock.id.as_str(), lock))
        .collect::<BTreeMap<_, _>>();
    let mut next_locks = Vec::new();
    let mut reports = Vec::new();
    for module in &source.modules {
        let assets = module
            .assets
            .iter()
            .map(|asset| ModuleAssetSource {
                module: Some(module.id.clone()),
                path: asset.path.clone(),
                bytes: asset.bytes.clone(),
            })
            .collect::<Vec<_>>();
        let digest = module_digest_with_assets(&module.module, &assets);
        let status = match current_locks.get(module.id.as_str()) {
            Some(lock)
                if lock.version == module.module.version
                    && lock.digest.as_ref() == Some(&digest) =>
            {
                "unchanged"
            }
            Some(_) => "updated",
            None => "added",
        };
        next_locks.push(ModuleLockSource {
            id: module.id.clone(),
            version: module.module.version.clone(),
            digest: Some(digest.clone()),
        });
        reports.push(json!({
            "id": &module.id,
            "version": &module.module.version,
            "digest": digest,
            "status": status,
        }));
    }
    next_locks.sort_by(|left, right| left.id.cmp(&right.id));
    let changed = source.project.modules != next_locks;
    if check_only && changed {
        return Err(FailureReport {
            ok: false,
            command: "project lock",
            diagnostics: vec![tool_diagnostic(
                diagnostic(
                    "module.lock.stale",
                    "project.modules",
                    "the project module locks are not up to date",
                ),
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::UpdateModuleLocks,
            )],
        });
    }
    let artifacts = if changed {
        let authored_locks = std::mem::replace(&mut source.project.modules, next_locks);
        let updated = render_project_module_locks(
            &source.project_bytes,
            &authored_locks,
            &source.project.modules,
        )
        .map_err(|diagnostic| {
            source_failure(
                "project lock",
                diagnostic,
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::UpdateModuleLocks,
            )
        })?;
        write_project_registry(project_path, &source.project_bytes, &updated).map_err(
            |diagnostic| {
                source_failure(
                    "project lock",
                    diagnostic,
                    DiagnosticArtifact::RegistryProject,
                    SuggestedAction::UpdateModuleLocks,
                )
            },
        )?;
        vec![artifact_report("registry.yaml", "text/yaml", &updated)]
    } else {
        Vec::new()
    };
    let compiled = compile(project_path, ProfileArg::Authoring, "project lock")?;
    Ok(SuccessReport {
        ok: true,
        command: "project lock",
        profile: ProfileArg::Authoring,
        revision: compiled.revision().to_owned(),
        findings: compiler_findings(&compiled),
        artifacts,
        explanation: Some(json!({
            "changed": changed,
            "modules": reports,
        })),
    })
}

fn generate(
    selector: ArtifactSelector,
    project_path: &Path,
    profile: ProfileArg,
    output: &Path,
) -> Result<SuccessReport, FailureReport> {
    let compiled = compile(project_path, profile, "generate")?;
    let selected =
        selected_artifacts(compiled.artifacts(), selector).map_err(|diagnostic| FailureReport {
            ok: false,
            command: "generate",
            diagnostics: vec![tool_diagnostic(
                diagnostic,
                DiagnosticArtifact::GeneratedArtifacts,
                SuggestedAction::SelectAvailableArtifact,
            )],
        })?;
    write_artifacts(output, &selected).map_err(|diagnostic| FailureReport {
        ok: false,
        command: "generate",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::GeneratedArtifacts,
            SuggestedAction::RetryArtifactGeneration,
        )],
    })?;
    let artifacts = selected
        .iter()
        .map(|artifact| artifact_report(&artifact.path, &artifact.media_type, &artifact.bytes))
        .collect();
    Ok(SuccessReport {
        ok: true,
        command: "generate",
        profile,
        revision: compiled.revision().to_owned(),
        findings: compiler_findings(&compiled),
        artifacts,
        explanation: None,
    })
}

fn planner_test(args: &ProjectPlannerTestArgs) -> Result<PlannerTestSuccessReport, FailureReport> {
    const COMMAND: &str = "project planner-test";
    let compiled = compile(&args.project, ProfileArg::Authoring, COMMAND)?;
    let entity = compiled.entities().get(&args.entity).ok_or_else(|| {
        planner_test_failure(
            "planner_test.entity.not_found",
            "entity",
            "select one compiled entity",
        )
    })?;
    let request = entity.change_request.as_ref().ok_or_else(|| {
        planner_test_failure(
            "planner_test.entity.not_request",
            "entity",
            "select a compiled change-request entity",
        )
    })?;
    let planner = request.planner.as_ref().ok_or_else(|| {
        planner_test_failure(
            "planner_test.planner.declarative",
            "entity",
            "the local planner test accepts only Rhai-backed request entities",
        )
    })?;

    let input_bytes = read_bounded_regular_file(
        &args.request,
        "planner_test.request.unavailable",
        MAX_PLANNER_TEST_REQUEST_BYTES,
    )
    .map_err(|diagnostic| {
        let (code, message) = if diagnostic.code == "source.file.bounds" {
            (
                "planner_test.request.bounds",
                "the synthetic request exceeds its fixed size bound",
            )
        } else {
            (
                "planner_test.request.unavailable",
                "the synthetic request must be a readable regular file without symbolic links",
            )
        };
        planner_test_failure(code, "request", message)
    })?;
    let input = parse_json_strict(&input_bytes).map_err(|_| {
        planner_test_failure(
            "planner_test.request.invalid",
            "request",
            "the synthetic request must be strict JSON",
        )
    })?;
    let input = input.as_object().ok_or_else(|| {
        planner_test_failure(
            "planner_test.request.invalid",
            "request",
            "the synthetic request must be one JSON object",
        )
    })?;
    if !bounded_planner_test_value(&Value::Object(input.clone()), 0) {
        return Err(planner_test_failure(
            "planner_test.request.bounds",
            "request",
            "the synthetic request exceeds the closed planner value bounds",
        ));
    }
    let declared_fields = planner.request_fields.iter().collect::<BTreeSet<_>>();
    if input.keys().any(|field| !declared_fields.contains(field)) {
        return Err(planner_test_failure(
            "planner_test.request.fields",
            "request",
            "the synthetic request may contain only planner-declared request fields",
        ));
    }

    let candidate = registry_server::rhai_planner::plan_change_request_effects(
        request,
        input,
        Instant::now() + PLANNER_TEST_DEADLINE,
    )
    .map_err(|error| {
        planner_test_failure(
            error.code(),
            "planner",
            "the closed Rhai planner refused the synthetic request",
        )
    })?;
    if candidate.planner_binding.kind != "rhai"
        || candidate.planner_binding.abi_identifier != planner.abi
        || candidate.planner_binding.script_sha256.as_deref()
            != Some(planner.script_sha256.as_str())
    {
        return Err(planner_test_failure(
            "planner_test.planner.binding",
            "planner",
            "the planner result did not preserve its compiled identity",
        ));
    }

    let mut field_mutations = 0usize;
    let mut dependency_count = 0usize;
    let effect_aliases = candidate
        .effects
        .iter()
        .enumerate()
        .map(|(index, effect)| (effect.id.as_str(), format!("effect-{}", index + 1)))
        .collect::<BTreeMap<_, _>>();
    let effects = candidate
        .effects
        .iter()
        .enumerate()
        .map(|(index, effect)| {
            let mut fields = effect
                .mutations
                .iter()
                .map(|mutation| match mutation {
                    registry_server::rhai_planner::CandidateChangeRequestMutation::Set {
                        field,
                        ..
                    }
                    | registry_server::rhai_planner::CandidateChangeRequestMutation::Clear {
                        field,
                    } => field.clone(),
                })
                .collect::<Vec<_>>();
            fields.sort();
            fields.dedup();
            field_mutations += effect.mutations.len();
            dependency_count += effect.depends_on.len();
            let mut depends_on = effect
                .depends_on
                .iter()
                .map(|dependency| {
                    effect_aliases
                        .get(dependency.as_str())
                        .cloned()
                        .ok_or_else(|| {
                            planner_test_failure(
                                "planner_test.planner.binding",
                                "planner",
                                "the planner result contains an unresolved effect dependency",
                            )
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            depends_on.sort();
            Ok(PlannerTestEffectReport {
                id: format!("effect-{}", index + 1),
                target_kind: match effect.target.binding {
                    registry_server::rhai_planner::CandidateChangeRequestTargetBinding::Existing {
                        ..
                    } => "existing",
                    registry_server::rhai_planner::CandidateChangeRequestTargetBinding::ReservedCreate {
                        ..
                    } => "reserved_create",
                },
                operation: operation_wire_name(effect.operation),
                fields,
                depends_on,
            })
        })
        .collect::<Result<Vec<_>, FailureReport>>()?;
    let disposition = match candidate.disposition {
        registry_server::model::CompiledChangeRequestDisposition::Apply => "apply",
        registry_server::model::CompiledChangeRequestDisposition::Queue => "queue",
    };
    let queue_reason = candidate
        .queue_reason
        .map(|reason| PlannerTestQueueReasonReport {
            code: reason.code,
            label: reason.label,
        });
    Ok(PlannerTestSuccessReport {
        ok: true,
        command: COMMAND,
        compiled_revision: compiled.revision().to_owned(),
        request_entity: entity.id.clone(),
        planner: PlannerTestIdentityReport {
            kind: "rhai",
            abi: planner.abi.clone(),
            script_sha256: planner.script_sha256.clone(),
        },
        disposition,
        queue_reason,
        counts: PlannerTestCountReport {
            effects: effects.len(),
            field_mutations,
            dependencies: dependency_count,
        },
        effects,
    })
}

fn bounded_planner_test_value(value: &Value, depth: usize) -> bool {
    use registry_server::rhai_planner::{
        MAXIMUM_ARRAY_ITEMS, MAXIMUM_MAP_ENTRIES, MAXIMUM_STRING_BYTES, MAXIMUM_VALUE_DEPTH,
    };

    if depth > MAXIMUM_VALUE_DEPTH {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(number) => number.as_i64().is_some(),
        Value::String(value) => value.len() <= MAXIMUM_STRING_BYTES,
        Value::Array(values) => {
            values.len() <= MAXIMUM_ARRAY_ITEMS
                && values
                    .iter()
                    .all(|value| bounded_planner_test_value(value, depth + 1))
        }
        Value::Object(values) => {
            values.len() <= MAXIMUM_MAP_ENTRIES
                && values.iter().all(|(key, value)| {
                    key.len() <= MAXIMUM_STRING_BYTES
                        && bounded_planner_test_value(value, depth + 1)
                })
        }
    }
}

fn planner_test_failure(code: &str, path: &str, message: &str) -> FailureReport {
    source_failure(
        "project planner-test",
        diagnostic(code, path, message),
        DiagnosticArtifact::PlannerTest,
        SuggestedAction::CorrectPlannerTestInput,
    )
}

fn explain(
    subject: ExplainSubject,
    project_path: &Path,
    profile: ProfileArg,
    scenario_path: Option<&Path>,
) -> Result<SuccessReport, FailureReport> {
    let compiled = compile(project_path, profile, "explain")?;
    let scenario_error = |diagnostic| FailureReport {
        ok: false,
        command: "explain",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        )],
    };
    let scenario = if let Some(path) = scenario_path {
        if !matches!(subject, ExplainSubject::Access) {
            return Err(scenario_error(diagnostic(
                "access.scenario.subject",
                "scenario",
                "--scenario is available only for explain access",
            )));
        }
        let bytes =
            read_bounded_source_file(path, "access.scenario.unavailable", "scenario", 65_536)
                .map_err(scenario_error)?;
        let source = parse_json_strict(&bytes).map_err(|_| scenario_error(diagnostic("access.scenario.invalid", "scenario", "provide a strict JSON access scenario with synthetic claims; duplicate keys and malformed JSON are refused")))?;
        let scenario = serde_json::from_value(source).map_err(|_| scenario_error(diagnostic("access.scenario.invalid", "scenario", "use entity, accessProfile, operation, optional readPath, and claims; claims accepts principalClaim, principal, scopes, purpose, and directClaims")))?;
        Some(
            registry_server::access_preview::preview_access(&compiled, scenario).map_err(
                |message| {
                    scenario_error(diagnostic("access.scenario.invalid", "scenario", message))
                },
            )?,
        )
    } else {
        None
    };
    let explanation = match subject {
        ExplainSubject::Model => explain_model(&compiled),
        ExplainSubject::Access => {
            if let Some(scenario) = scenario {
                serde_json::to_value(scenario)
            } else {
                serde_json::to_value(registry_server::access::explain_access(&compiled))
            }
        }
        ExplainSubject::Routes => explain_routes(&compiled),
        ExplainSubject::Queries => explain_queries(&compiled),
        ExplainSubject::Actions => explain_actions(&compiled),
        ExplainSubject::ChangeRequests => explain_change_requests(&compiled),
        ExplainSubject::Events => serde_json::to_value(compiled.event_deliveries()),
    }
    .map_err(|_| FailureReport {
        ok: false,
        command: "explain",
        diagnostics: vec![tool_diagnostic(
            diagnostic(
                "explain.render.failed",
                "explain",
                "the compiled inventory could not be rendered",
            ),
            DiagnosticArtifact::CompiledInventory,
            SuggestedAction::RetryInventoryExplanation,
        )],
    })?;
    Ok(SuccessReport {
        ok: true,
        command: "explain",
        profile,
        revision: compiled.revision().to_owned(),
        findings: compiler_findings(&compiled),
        artifacts: Vec::new(),
        explanation: Some(explanation),
    })
}

fn compile(
    project_path: &Path,
    profile: ProfileArg,
    command: &'static str,
) -> Result<registry_server::CompiledRegistry, FailureReport> {
    let source = capture_project_source(project_path).map_err(|diagnostic| {
        source_failure(
            command,
            diagnostic,
            DiagnosticArtifact::RegistryProject,
            SuggestedAction::CorrectAuthoringSource,
        )
    })?;
    compile_captured_project(&source, profile, command)
}

fn compile_captured_project(
    source: &CapturedProjectSource,
    profile: ProfileArg,
    command: &'static str,
) -> Result<registry_server::CompiledRegistry, FailureReport> {
    let modules = source
        .modules
        .iter()
        .map(|module| module.module.clone())
        .collect::<Vec<_>>();
    let assets = source
        .project_assets
        .iter()
        .map(|asset| ModuleAssetSource {
            module: None,
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        })
        .chain(source.modules.iter().flat_map(|module| {
            module.assets.iter().map(|asset| ModuleAssetSource {
                module: Some(module.id.clone()),
                path: asset.path.clone(),
                bytes: asset.bytes.clone(),
            })
        }))
        .collect::<Vec<_>>();
    compile_project_with_assets(&source.project, &modules, &assets, profile.into()).map_err(
        |failure| FailureReport {
            ok: false,
            command,
            diagnostics: failure
                .diagnostics()
                .iter()
                .cloned()
                .map(|diagnostic| {
                    tool_diagnostic(
                        remap_derived_diagnostic_path(diagnostic, source),
                        DiagnosticArtifact::RegistryProject,
                        SuggestedAction::CorrectAuthoringSource,
                    )
                })
                .collect(),
        },
    )
}

fn compiler_findings(compiled: &CompiledRegistry) -> Vec<ToolDiagnostic> {
    compiled
        .findings()
        .iter()
        .cloned()
        .map(|diagnostic| {
            tool_diagnostic(
                diagnostic,
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::ReviewAuthoringFinding,
            )
        })
        .collect()
}

fn source_failure(
    command: &'static str,
    diagnostic: Diagnostic,
    artifact: DiagnosticArtifact,
    action: SuggestedAction,
) -> FailureReport {
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(diagnostic, artifact, action)],
    }
}

fn capture_project_source(project_path: &Path) -> Result<CapturedProjectSource, Diagnostic> {
    validate_project_directory(project_path)?;
    let project_bytes = read_bounded_source_file(
        &project_path.join("registry.yaml"),
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    let project = parse_project_yaml(&project_bytes).map_err(first_diagnostic)?;
    let project_assets = load_project_planner_asset_files(project_path, &project)?;
    let modules = load_module_files(project_path, &project)?
        .into_iter()
        .map(|(id, bytes)| {
            let module = parse_module_yaml(&bytes).map_err(first_diagnostic)?;
            ensure_module_id_matches_directory(&module.id, &id)?;
            let assets = load_module_asset_files(project_path, &id, &module)?;
            Ok(CapturedModuleSource {
                id,
                module,
                bytes,
                assets,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    ensure_every_lock_has_a_source(&project, &modules)?;
    Ok(CapturedProjectSource {
        project,
        project_bytes,
        project_assets,
        modules,
    })
}

/// A module directory and the id its source declares are one name, so a rename
/// is reported by every command that reads the project, not only by locking.
fn ensure_module_id_matches_directory(
    declared_id: &str,
    directory_id: &str,
) -> Result<(), Diagnostic> {
    if declared_id == directory_id {
        return Ok(());
    }
    Err(diagnostic(
        "source.module.id_mismatch",
        &format!("modules/{directory_id}/module.yaml"),
        "the module source id must match its directory name",
    ))
}

/// A lock without a source is a deleted module, reported the same way wherever
/// the project is read. Module ids stay out of the sentence.
fn ensure_every_lock_has_a_source(
    project: &RegistryProject,
    modules: &[CapturedModuleSource],
) -> Result<(), Diagnostic> {
    let discovered = modules
        .iter()
        .map(|module| module.id.as_str())
        .collect::<BTreeSet<_>>();
    if project
        .modules
        .iter()
        .any(|lock| !discovered.contains(lock.id.as_str()))
    {
        return Err(diagnostic(
            "module.lock.source_missing",
            "project.modules",
            "every module lock must have a discovered module source",
        ));
    }
    Ok(())
}

fn capture_project_source_for_lock(
    project_path: &Path,
) -> Result<CapturedProjectSource, Diagnostic> {
    validate_project_directory(project_path)?;
    let project_bytes = read_bounded_source_file(
        &project_path.join("registry.yaml"),
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    let project = parse_project_yaml(&project_bytes).map_err(first_diagnostic)?;
    let project_assets = load_project_planner_asset_files(project_path, &project)?;
    let mut locked = BTreeSet::new();
    for lock in &project.modules {
        if !locked.insert(lock.id.as_str()) {
            return Err(diagnostic(
                "module.lock.duplicate",
                "project.modules",
                "module lock identifiers must be unique",
            ));
        }
    }
    let modules = discover_module_files(project_path)?
        .into_iter()
        .map(|(directory_id, bytes)| {
            let module = parse_module_yaml(&bytes).map_err(first_diagnostic)?;
            ensure_module_id_matches_directory(&module.id, &directory_id)?;
            let assets = load_module_asset_files(project_path, &directory_id, &module)?;
            Ok(CapturedModuleSource {
                id: directory_id,
                module,
                bytes,
                assets,
            })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    ensure_every_lock_has_a_source(&project, &modules)?;
    Ok(CapturedProjectSource {
        project,
        project_bytes,
        project_assets,
        modules,
    })
}

fn load_module_files(
    project_path: &Path,
    project: &RegistryProject,
) -> Result<Vec<(String, Vec<u8>)>, Diagnostic> {
    let modules_directory = project_path.join("modules");
    match fs::symlink_metadata(&modules_directory) {
        Ok(_) => validate_directory(&modules_directory, "source.modules.invalid")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err(diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            ));
        }
    }
    let locked: std::collections::BTreeSet<&str> = project
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect();
    let mut module_paths = Vec::new();
    for entry in fs::read_dir(&modules_directory).map_err(|_| {
        diagnostic(
            "source.modules.unreadable",
            "modules",
            "module sources cannot be read",
        )
    })? {
        let entry = entry.map_err(|_| {
            diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            )
        })?;
        let file_type = entry.file_type().map_err(|_| {
            diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            )
        })?;
        // Finder metadata is not an authored module. Ignore only this exact
        // regular file; every other unexpected entry remains fail-closed.
        if entry.file_name() == ".DS_Store" && file_type.is_file() {
            continue;
        }
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(diagnostic(
                "source.modules.invalid",
                "modules",
                "module sources must be directories and must not be symbolic links",
            ));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(diagnostic(
                "source.modules.invalid",
                "modules",
                "module source names must be valid UTF-8 identifiers",
            ));
        };
        if !locked.contains(name) {
            return Err(diagnostic(
                "source.modules.unlocked",
                "modules",
                "every authored module directory must be declared by the project module lock",
            ));
        }
        module_paths.push((name.to_owned(), entry.path().join("module.yaml")));
    }
    module_paths.sort_by(|left, right| left.0.cmp(&right.0));
    module_paths
        .into_iter()
        .map(|(id, path)| {
            let bytes = read_bounded_source_file(
                &path,
                "source.module.missing",
                &format!("modules/{id}/module.yaml"),
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )?;
            Ok((id, bytes))
        })
        .collect()
}

fn discover_module_files(project_path: &Path) -> Result<Vec<(String, Vec<u8>)>, Diagnostic> {
    let modules_directory = project_path.join("modules");
    match fs::symlink_metadata(&modules_directory) {
        Ok(_) => validate_directory(&modules_directory, "source.modules.invalid")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => {
            return Err(diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            ));
        }
    }
    let mut module_paths = Vec::new();
    for entry in fs::read_dir(&modules_directory).map_err(|_| {
        diagnostic(
            "source.modules.unreadable",
            "modules",
            "module sources cannot be read",
        )
    })? {
        let entry = entry.map_err(|_| {
            diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            )
        })?;
        let file_type = entry.file_type().map_err(|_| {
            diagnostic(
                "source.modules.unreadable",
                "modules",
                "module sources cannot be read",
            )
        })?;
        if entry.file_name() == ".DS_Store" && file_type.is_file() {
            continue;
        }
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(diagnostic(
                "source.modules.invalid",
                "modules",
                "module sources must be directories and must not be symbolic links",
            ));
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(diagnostic(
                "source.modules.invalid",
                "modules",
                "module source names must be valid UTF-8 identifiers",
            ));
        };
        module_paths.push((name.to_owned(), entry.path().join("module.yaml")));
    }
    module_paths.sort_by(|left, right| left.0.cmp(&right.0));
    module_paths
        .into_iter()
        .map(|(id, path)| {
            let bytes = read_bounded_source_file(
                &path,
                "source.module.missing",
                &format!("modules/{id}/module.yaml"),
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )?;
            Ok((id, bytes))
        })
        .collect()
}

fn load_project_planner_asset_files(
    project_path: &Path,
    project: &RegistryProject,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    let paths = project
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.clone())
        })
        .collect::<BTreeSet<_>>();
    load_planner_asset_files(project_path, "registry.yaml", paths)
}

fn load_module_asset_files(
    project_path: &Path,
    module_id: &str,
    module: &RegistryModule,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    let mut paths = BTreeSet::new();
    for entity in &module.entities {
        for derived in &entity.derived {
            validate_module_sql_asset_path(module_id, &derived.sql)?;
            if !paths.insert(derived.sql.clone()) {
                return Err(diagnostic(
                    "source.module_asset.duplicate",
                    &format!("modules/{module_id}/module.yaml"),
                    "derived SQL assets must be unique within a module",
                ));
            }
        }
    }
    for extension in &module.extend_entities {
        for derived in &extension.derived {
            validate_module_sql_asset_path(module_id, &derived.sql)?;
            if !paths.insert(derived.sql.clone()) {
                return Err(diagnostic(
                    "source.module_asset.duplicate",
                    &format!("modules/{module_id}/module.yaml"),
                    "derived SQL assets must be unique within a module",
                ));
            }
        }
    }
    let mut assets = paths
        .into_iter()
        .map(|path| {
            let bytes = read_bounded_source_file(
                &project_path.join("modules").join(module_id).join(&path),
                "source.module_asset.missing",
                &format!("modules/{module_id}/{path}"),
                MAX_DERIVED_SQL_ASSET_BYTES,
            )?;
            if bytes.is_empty() {
                return Err(diagnostic(
                    "source.module_asset.bounds",
                    &format!("modules/{module_id}/{path}"),
                    "derived SQL assets must be non-empty bounded regular files",
                ));
            }
            Ok(CapturedModuleAssetSource { path, bytes })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let planner_paths = module
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.clone())
        })
        .chain(module.extend_entities.iter().filter_map(|extension| {
            extension
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| planner.script.clone())
        }))
        .collect::<BTreeSet<_>>();
    assets.extend(load_planner_asset_files(
        &project_path.join("modules").join(module_id),
        &format!("modules/{module_id}/module.yaml"),
        planner_paths,
    )?);
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(assets)
}

fn load_planner_asset_files(
    origin: &Path,
    declaring_path: &str,
    paths: BTreeSet<String>,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    paths
        .into_iter()
        .map(|path| {
            validate_rhai_planner_asset_path(declaring_path, &path)?;
            let bytes = read_bounded_regular_file(
                &origin.join(&path),
                "source.planner_asset.missing",
                MAX_RHAI_PLANNER_SOURCE_BYTES,
            )?;
            if bytes.is_empty() {
                return Err(diagnostic(
                    "source.planner_asset.bounds",
                    declaring_path,
                    "Rhai planner scripts must be non-empty bounded regular files",
                ));
            }
            Ok(CapturedModuleAssetSource { path, bytes })
        })
        .collect()
}

fn validate_rhai_planner_asset_path(
    declaring_path: &str,
    asset_path: &str,
) -> Result<(), Diagnostic> {
    if asset_path.is_empty()
        || asset_path.len() > MAX_RHAI_PLANNER_PATH_BYTES
        || asset_path.contains('\\')
        || asset_path.ends_with('/')
        || !asset_path.ends_with(".rhai")
    {
        return Err(planner_asset_path_diagnostic(declaring_path));
    }
    let path = Path::new(asset_path);
    let components = path.components().collect::<Vec<_>>();
    if path.is_absolute()
        || components.len() > 12
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.to_str() != Some(asset_path)
        || components
            .iter()
            .filter_map(|component| match component {
                Component::Normal(component) => component.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/")
            != asset_path
    {
        return Err(planner_asset_path_diagnostic(declaring_path));
    }
    Ok(())
}

fn planner_asset_path_diagnostic(declaring_path: &str) -> Diagnostic {
    diagnostic(
        "source.planner_asset.path_unsafe",
        declaring_path,
        "Rhai planner scripts must use bounded declaring-origin-relative .rhai paths",
    )
}

fn validate_module_sql_asset_path(module_id: &str, asset_path: &str) -> Result<(), Diagnostic> {
    if asset_path.is_empty()
        || asset_path.len() > 512
        || asset_path.contains('\\')
        || asset_path.ends_with('/')
        || !asset_path.ends_with(".sql")
    {
        return Err(module_asset_path_diagnostic(module_id));
    }
    let path = Path::new(asset_path);
    let components = path.components().collect::<Vec<_>>();
    if path.is_absolute()
        || components.len() > 12
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.to_str() != Some(asset_path)
        || components
            .iter()
            .filter_map(|component| match component {
                Component::Normal(component) => component.to_str(),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/")
            != asset_path
    {
        return Err(module_asset_path_diagnostic(module_id));
    }
    Ok(())
}

fn module_asset_path_diagnostic(module_id: &str) -> Diagnostic {
    diagnostic(
        "source.module_asset.path_unsafe",
        &format!("modules/{module_id}/module.yaml"),
        "derived SQL assets must be bounded module-relative .sql paths",
    )
}

/// The module digest placeholder the initialized project carries until this
/// command computes it from the module it writes beside the project.
const INIT_MODULE_DIGEST_PLACEHOLDER: &str = "<module-digest>";

/// The module the initialized project locks; `modules/record-notes/module.yaml`.
const INIT_MODULE_PATH: &str = "modules/record-notes/module.yaml";

const INIT_README: &[u8] = br#"# Registry project

`registry-serverctl init` wrote this project. It is a working example, not a
blank page: every identifier is a placeholder chosen to be obviously synthetic,
and every file carries comments saying what a block does and what you change.

## Files

| File | What it holds |
| --- | --- |
| `registry.yaml` | The registry: its identity and package identity, the catalogue projection, one closed vocabulary, two entities, and two access profiles. Every command reads this file. |
| `modules/record-notes/module.yaml` | A module: a reusable part of the model, versioned on its own and pinned by content digest in the project's `modules` list. |
| `tests/journeys.yaml` | The requests `registry-serverctl test` replays over HTTP against a throwaway database before a package is built. |
| `runtime.example.yaml` | An example of the operator's runtime configuration. No command reads it; copy it out of the project and replace every value. |

## What the example models

Two entities: `record-group` is public reference data, and `record` is the
internal record that points at a group through a `reference` field and carries a
`status` drawn from a closed vocabulary. Two access profiles read them: an
`operator` that runs the whole registry, and a `record-reader` whose rows are
restricted by a claim on its own credentials.

Replace this model with your own. The names are deliberately generic so that
nothing here reads as advice about what your registry should contain.

## Next commands

```sh
registry-serverctl check .
registry-serverctl explain queries .
registry-serverctl explain events .
```

`check` compiles the project and reports problems and findings. It reports one
finding for this project on purpose: `access.profile.unrestricted_collection`,
because the `operator` profile can list every record. The comment above that
profile says how to close it.

`explain` prints what the compiled project exposes, such as the query surface
each profile gets and the events the package would emit.

Edit `modules/record-notes/module.yaml`, then re-pin it:

```sh
registry-serverctl project lock .
```

`registry-serverctl test` replays `tests/journeys.yaml` over HTTP. It needs more
than the project: an empty PostgreSQL database, a runtime configuration built
from `runtime.example.yaml`, and one credential per journey step bound in a
credentials file. The operate documentation below walks through preparing them.

## Documentation

- Configure a registry: <https://docs.registrystack.org/configure/registry-server/>
- Operate a registry: <https://docs.registrystack.org/operate/registry-server/>
- Every configuration key: <https://docs.registrystack.org/reference/registry-server-configuration/>
- `registry-serverctl` commands: <https://docs.registrystack.org/reference/cli/registry-serverctl/>
"#;

const INIT_REGISTRY_PROJECT: &[u8] =
    br#"# The registry project: one document that decides the model, the access rules,
# and the catalogue description of a single registry. Every registry-serverctl
# command reads it. Replace the identifiers, titles, and URLs below with your
# own; every value here is a placeholder chosen to be obviously synthetic.
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject

# Registry identity. `canonicalBaseIri` is the stable base of the IRIs this
# registry publishes, so point it at a hostname you control before a production
# package. Names under `.example.invalid` never resolve.
registry:
  id: generic-registry
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://generic-registry.example.invalid

# Package identity binds a compiled package to one environment, one instance,
# and one reviewed source revision. Raise `sequence` by one for each package you
# build; the runtime refuses a package whose identity does not match its
# configuration file.
package:
  environment: development
  instanceId: generic-registry-1
  sequence: 1
  sourceRevision: generic-registry-0.1.0

# The Registry Manifest projection is the catalogue description this registry
# publishes about itself. `accessProfile` and `classificationCeiling` bound what
# the projection may describe; they never grant access to a caller.
manifestProjection:
  accessProfile: operator
  classificationCeiling: internal
  catalog:
    baseUrl: https://generic-registry.example.invalid
    title: Generic Registry Catalogue
    description: Placeholder catalogue description; replace it with your own.
    publisher:
      id: generic-registry-authority
      name: Generic Registry Authority
      iri: https://generic-registry.example.invalid/authority
  datasets:
    - id: generic-registry
      title: Generic Registry
      description: Placeholder dataset description; replace it with your own.
      owner: Generic Registry Authority
      status: under_development
  dataServices:
    - id: generic-registry-api
      title: Generic Registry API
      endpointUrl: https://generic-registry.example.invalid
      servesDatasets: [generic-registry]
  publicService:
    id: generic-registry-service
    title: Generic Registry Service

# A vocabulary is a closed code list. A `vocabulary-code` field accepts only
# these values, and the compiler refuses any other value at authoring time.
vocabularies:
  - id: record-status
    values: [draft, active, retired]

entities:
  # Reference data the records point at. It is classified `public` because a
  # list of group codes discloses nothing on its own; the records themselves
  # stay `internal`.
  - id: record-group
    primaryDataset: generic-registry
    route: record-groups
    mutationMode: mutable
    classification: public
    fields:
      - {id: code, type: string, required: true, maxLength: 64, classification: public}
      - {id: label, type: string, required: true, maxLength: 200, classification: public}
    constraints:
      - {kind: unique, fields: [code]}

  # The registry's records. `group` is a reference: the server stores the target
  # record's identifier and refuses a value that names no `record-group`.
  # `status` is a vocabulary code drawn from the `record-status` list above.
  # Neither is `required`, so a create may omit it.
  #
  # An entity may also declare `events`, which project chosen fields of a
  # committed change to a webhook destination the deployment binds by name.
  # This project declares none: a package refuses to activate until the runtime
  # configuration binds every destination its events name, so add an event and
  # its binding together.
  - id: record
    primaryDataset: generic-registry
    route: records
    mutationMode: mutable
    classification: internal
    fields:
      - {id: code, type: string, required: true, maxLength: 64, classification: internal}
      - {id: label, type: string, required: true, maxLength: 200, classification: internal}
      - {id: group, type: reference, target: record-group, classification: internal}
      - {id: status, type: vocabulary-code, vocabulary: record-status, classification: internal}
    constraints:
      - {kind: unique, fields: [code]}

# A token selects one profile per request, and that profile decides everything
# the request may touch. Profiles are never merged, and naming one in a request
# grants nothing the profile does not already allow.
accessProfiles:
  # The registry-wide operator. `readableFields` decide what a response may
  # carry, `writableFields` what a create or patch may set, and
  # `filterableFields` which fields a caller may filter and sort a list by.
  #
  # `check` reports `access.profile.unrestricted_collection` for this profile:
  # it can list every record, and a caller-supplied filter is not authorization.
  # That is intended for a single operations team running the whole registry.
  # Close it by giving the grant a `rowBoundaries` entry, the way `record-reader`
  # below does, or by removing `list` from its operations.
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry:generic:operate]
    requiredPurposes: [registry-operations]
    grants:
      - entity: record-group
        operations: [create, get, list]
        readableFields: [code, label]
        writableFields: [code, label]
        filterableFields: [code]
      - entity: record
        operations: [create, get, list, patch]
        readableFields: [code, label, group, status]
        writableFields: [code, label, group, status]
        filterableFields: [code, status]

  # A row-restricted reader. A row boundary compares a declared field against a
  # verified claim on the caller's credentials, so this profile reads only the
  # records whose `status` matches its own claim. `equals` compares against one
  # claim value; `in` compares against a claim carrying a list of them, which
  # the authorization server must then issue as a JSON array. Bind the boundary
  # to whatever field carries your registry's tenancy: an owning office, a
  # jurisdiction code, a programme. Decide deliberately which profiles may write
  # that field, because a profile that can patch it moves records in and out of
  # another caller's rows. Here the operator may, and `tests/journeys.yaml`
  # shows a record leaving this reader's rows when its status changes.
  - id: record-reader
    principalClaim: registry_principal
    requiredScopes: [registry:generic:read]
    requiredPurposes: [registry-reporting]
    grants:
      - entity: record
        operations: [get, list]
        readableFields: [code, label, group, status]
        filterableFields: [code]
        rowBoundaries:
          - {field: status, claim: registry_record_status, operator: equals}

# Modules contribute to the model from their own files under `modules/`.
# `registry-serverctl project lock` writes the version and content digest below;
# a stale digest is a compile error, which keeps a reviewed project pinned to the
# module content it was reviewed with. Re-run `project lock` after every module edit.
modules:
  - id: "record-notes"
    version: "0.1.0"
    digest: "<module-digest>"
"#;

const INIT_MODULE: &[u8] =
    br#"# A module contributes to the model from its own file, so a reusable part of a
# registry can be reviewed and versioned separately from the project that adopts
# it. `extendEntities` adds to an entity the module does not own.
#
# Raise `version` and re-run `registry-serverctl project lock` after every edit
# here; the project's `modules` entry pins this file by content digest.
id: record-notes
version: 0.1.0
extendEntities:
  # An optional field: without `required: true`, existing records stay valid and
  # a create may omit it. Adding a field to the model grants nobody access to
  # it; list it in an access profile's `readableFields` and `writableFields`
  # before a caller can see or set it.
  - entity: record
    fields:
      - {id: internal-note, type: string, maxLength: 500, classification: internal}
"#;

const INIT_RUNTIME_EXAMPLE: &[u8] =
    br#"# An example runtime configuration. It is not read by any command: copy it to a
# file the operator keeps outside this project, then replace every value below.
# The runtime file is a deployment artifact. It binds one compiled package to
# one database, one token issuer, and one listener. It never holds a credential:
# a `secret:file/<name>` reference names an owner-only file under the file
# provider root, and `secret:env/<NAME>` an environment variable.
# Every host here is under `.example.invalid`, which never resolves.
apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig

# Where the server listens, and whether it trusts an upstream proxy's client
# address. `direct` means nothing is in front of it.
listener:
  bind: 127.0.0.1:8080
  trustedProxy: direct

# The environment, instance, and database this file may serve. `environment`
# and `instanceId` must equal the `package` block in registry.yaml, and
# `databaseId` the `--database-id` given to `test` and `package`.
identity:
  environment: development
  instanceId: generic-registry-1
  databaseId: generic-registry-db-1
  databaseInitializationEnvironment: development

# The directory holding the owner-only files the references below name.
secretProviders:
  file:
    root: /replace/me/secrets

# Two connection URLs and the two PostgreSQL roles the package's policies are
# written for: one role migrates, the other serves requests.
database:
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 8
  roles:
    migration: registry_migration
    runtime: registry_runtime

# The activated package directory and the revision it must be.
# `registry-serverctl package` reports `activeRevision`; `compilerSourceRevision`
# must equal `package.sourceRevision` in registry.yaml.
package:
  root: /replace/me/packages/build-1/package
  trustAnchorPath: /replace/me/package-trust-anchor.json
  compilerSourceRevision: generic-registry-0.1.0
  activeRevision: sha256:replace-me-with-the-revision-package-reported
  activeSequence: 1

# The token issuer this deployment accepts, and the claim names that carry
# Registry authority. `authorityClaims` must name the claims the access profiles
# in registry.yaml read: `principalClaim`, and the claims row boundaries compare.
authentication:
  oidc:
    issuer: https://issuer.example.invalid
    audience: generic-registry
    allowedAlgorithm: ES256
    accessTokenType: at+jwt
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [generic-registry-client]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 30000
    jwksSource:
      kind: discovery
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose

# The key that chains the audit journal and the secret that signs pagination
# cursors. Losing either invalidates existing chains or cursors, so generate
# them once and keep them.
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key

# One binding for every webhook destination the package's events declare, and
# no others: activation refuses a missing binding and an extra one alike. This
# project declares no event, so the map is empty. A destination's URL, shared
# HMAC key, and retry ceilings live only here, never in the project.
eventDestinations: {}
"#;

const INIT_JOURNEYS: &[u8] =
    br#"# Project journeys: the requests `registry-serverctl test` replays over real
# HTTP, with real credentials, against a throwaway database before a package is
# built. Every entity, profile, field, and claim below is resolved against the
# compiled project first, so a journey can never reach past what a profile
# already allows. The claims below are synthetic; credentials never belong here,
# `registry-serverctl test` binds one per step from its own credentials file.
apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: record-lifecycle
    steps:
      # `capture` names the created record so later steps can refer to it, by
      # `recordRef` for a target and by `{recordRef: ...}` for a reference value.
      - id: create-record-group
        entity: record-group
        accessProfile: operator
        claims: &operator_claims
          principal: generic-registry-operator
          scopes: [registry:generic:operate]
          purpose: registry-operations
        request:
          operation: create
          data: {code: group-a, label: Example group}
        expect:
          outcome: success
          status: 201
          fields: {code: group-a, label: Example group}
        capture: example-group
      - id: create-record
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request:
          operation: create
          data:
            code: example
            label: Example record
            group: {recordRef: example-group}
            status: active
        expect:
          outcome: success
          status: 201
          fields: {code: example, label: Example record, status: active}
        capture: example-record
      - id: get-record
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request: {operation: get, recordRef: example-record}
        expect:
          outcome: success
          status: 200
          fields: {code: example, label: Example record, status: active}
      # The row boundary on `record-reader` is authorization, not a filter: the
      # caller's own claim names the status it may read, and this record carries
      # it.
      - id: read-record-within-the-claim
        entity: record
        accessProfile: record-reader
        claims: &reader_claims
          principal: generic-registry-reader
          scopes: [registry:generic:read]
          purpose: registry-reporting
          directClaims:
            registry_record_status: active
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 1}
      # `etagRef` sends the captured record's ETag as `If-Match`, so a patch
      # fails rather than overwriting a concurrent change.
      - id: retire-record
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request:
          operation: patch
          recordRef: example-record
          etagRef: example-record
          changes:
            - {field: status, value: retired}
        expect:
          outcome: success
          status: 200
          fields: {code: example, label: Example record, status: retired}
      # The same request from the same reader now returns nothing: the record
      # moved outside the rows its claim allows.
      - id: read-record-outside-the-claim
        entity: record
        accessProfile: record-reader
        claims: *reader_claims
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
      - id: list-records
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 1}
"#;

fn init_files() -> BTreeMap<String, Vec<u8>> {
    let module = parse_module_yaml(INIT_MODULE).expect("the initialized module parses");
    let registry = String::from_utf8(INIT_REGISTRY_PROJECT.to_vec())
        .expect("the initialized project is UTF-8")
        .replace(
            INIT_MODULE_DIGEST_PLACEHOLDER,
            &module_digest_with_assets(&module, &[]),
        );
    BTreeMap::from([
        ("README.md".to_owned(), INIT_README.to_vec()),
        (INIT_MODULE_PATH.to_owned(), INIT_MODULE.to_vec()),
        ("registry.yaml".to_owned(), registry.into_bytes()),
        (
            "runtime.example.yaml".to_owned(),
            INIT_RUNTIME_EXAMPLE.to_vec(),
        ),
        (FIXTURE_JOURNEYS_PATH.to_owned(), INIT_JOURNEYS.to_vec()),
    ])
}

/// The media type an initialized project's file is reported with.
fn init_media_type(path: &str) -> &'static str {
    if path.ends_with(".md") {
        "text/markdown"
    } else {
        "text/yaml"
    }
}

/// Writes `locks` into the authored project source.
///
/// When the authored lock entries already name the same module ids in the same order, only the
/// locked values move, so the version and digest lines are patched where they stand and every
/// comment an author wrote inside the `modules` block survives. A project that gained or lost a
/// module, or whose `modules` block is not the ordinary block list the in-place patch understands,
/// has the whole block rewritten instead: that normalizes the entries a lock refresh has to
/// reorder, at the cost of the comments between them.
fn render_project_module_locks(
    original: &[u8],
    authored: &[ModuleLockSource],
    locks: &[ModuleLockSource],
) -> Result<Vec<u8>, Diagnostic> {
    let same_modules = authored.len() == locks.len()
        && authored
            .iter()
            .zip(locks)
            .all(|(authored, lock)| authored.id == lock.id);
    if same_modules {
        if let Ok(patched) = project_migration::update_module_locks(original, locks) {
            return Ok(patched);
        }
    }
    render_project_with_module_locks(original, locks)
}

fn render_project_with_module_locks(
    original: &[u8],
    locks: &[ModuleLockSource],
) -> Result<Vec<u8>, Diagnostic> {
    let original = std::str::from_utf8(original).map_err(|_| {
        diagnostic(
            "module.lock.render_failed",
            "registry.yaml",
            "the project module locks could not be rendered",
        )
    })?;
    let mut rendered = replace_top_level_modules_block(original, &module_locks_yaml(locks));
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    parse_project_yaml(rendered.as_bytes()).map_err(|_| {
        diagnostic(
            "module.lock.render_failed",
            "registry.yaml",
            "the project module locks could not be rendered",
        )
    })?;
    Ok(rendered.into_bytes())
}

fn replace_top_level_modules_block(source: &str, replacement: &str) -> String {
    let lines = source.split_inclusive('\n').collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| top_level_key(line) == Some("modules"));
    let Some(start) = start else {
        let mut rendered = source.trim_end_matches('\n').to_owned();
        if !rendered.is_empty() {
            rendered.push_str("\n\n");
        }
        rendered.push_str(replacement);
        return rendered;
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| top_level_key(line).is_some())
        .map(|(index, _)| index)
        .unwrap_or(lines.len());
    let mut rendered = String::new();
    rendered.push_str(&lines[..start].concat());
    rendered.push_str(replacement);
    if end < lines.len() {
        if !rendered.ends_with("\n\n") {
            rendered.push('\n');
        }
        rendered.push_str(&lines[end..].concat());
    }
    rendered
}

fn top_level_key(line: &str) -> Option<&str> {
    if line.starts_with(char::is_whitespace) || line.starts_with('#') {
        return None;
    }
    let trimmed = line.trim_end();
    let (key, _) = trimmed.split_once(':')?;
    if key.is_empty()
        || key
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return None;
    }
    Some(key)
}

fn module_locks_yaml(locks: &[ModuleLockSource]) -> String {
    let mut rendered = String::from("modules:\n");
    for lock in locks {
        rendered.push_str("  - id: ");
        rendered.push_str(&yaml_string(&lock.id));
        rendered.push_str("\n    version: ");
        rendered.push_str(&yaml_string(&lock.version));
        rendered.push_str("\n    digest: ");
        rendered.push_str(&yaml_string(
            lock.digest
                .as_deref()
                .expect("project lock always writes module digests"),
        ));
        rendered.push('\n');
    }
    rendered
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization cannot fail")
}

fn write_project_registry(
    project_path: &Path,
    original: &[u8],
    updated: &[u8],
) -> Result<(), Diagnostic> {
    let registry_path = project_path.join("registry.yaml");
    let current = read_bounded_source_file(
        &registry_path,
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    if current != original {
        return Err(diagnostic(
            "module.lock.concurrent_change",
            "registry.yaml",
            "the project source changed before module locks could be written",
        ));
    }
    let parent = registry_path.parent().ok_or_else(|| {
        diagnostic(
            "module.lock.write_failed",
            "registry.yaml",
            "the project module locks could not be written",
        )
    })?;
    validate_directory_for(
        parent,
        "module.lock.write_failed",
        "registry.yaml",
        "the project directory is not available",
        "the project directory must be a directory and must not be a symbolic link",
    )?;
    let temporary = parent.join(format!(
        ".registry-serverctl-lock-{}-{}.tmp",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let write_result = (|| {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| {
                diagnostic(
                    "module.lock.write_failed",
                    "registry.yaml",
                    "the project module locks could not be written",
                )
            })?;
        file.write_all(updated).map_err(|_| {
            diagnostic(
                "module.lock.write_failed",
                "registry.yaml",
                "the project module locks could not be written",
            )
        })?;
        file.sync_all().map_err(|_| {
            diagnostic(
                "module.lock.write_failed",
                "registry.yaml",
                "the project module locks could not be written",
            )
        })?;
        fs::rename(&temporary, &registry_path).map_err(|_| {
            diagnostic(
                "module.lock.write_failed",
                "registry.yaml",
                "the project module locks could not be written",
            )
        })
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

struct MigrationWriteTarget {
    relative_path: String,
    path: PathBuf,
    parent: PathBuf,
    original: Vec<u8>,
    updated: Vec<u8>,
    metadata: fs::Metadata,
    transaction_directory: PathBuf,
    staged_path: PathBuf,
    backup_path: PathBuf,
}

#[derive(Clone, Copy, Default)]
enum MigrationWriteFault {
    #[default]
    None,
    #[cfg(test)]
    ConcurrentChange(usize),
    #[cfg(test)]
    Stage(usize),
    #[cfg(test)]
    Commit(usize),
}

fn write_migration_files(
    project_path: &Path,
    files: &BTreeMap<String, (Vec<u8>, Vec<u8>)>,
) -> Result<(), Diagnostic> {
    write_migration_files_with_fault(project_path, files, MigrationWriteFault::None)
}

fn write_migration_files_with_fault(
    project_path: &Path,
    files: &BTreeMap<String, (Vec<u8>, Vec<u8>)>,
    _fault: MigrationWriteFault,
) -> Result<(), Diagnostic> {
    // Preflight the complete write set before creating even a staging
    // directory. A refusal here therefore cannot partially migrate a project.
    let mut targets = Vec::with_capacity(files.len());
    for (relative_path, (original, updated)) in files {
        let relative = Path::new(relative_path);
        if relative.is_absolute()
            || has_parent_component(relative)
            || relative.file_name().is_none()
        {
            return Err(migration_write_diagnostic(
                "project.migrate.write_failed",
                relative_path,
            ));
        }
        let path = project_path.join(relative);
        let parent = path.parent().map(Path::to_owned).ok_or_else(|| {
            migration_write_diagnostic("project.migrate.write_failed", relative_path)
        })?;
        validate_directory_for(
            &parent,
            "project.migrate.write_failed",
            relative_path,
            "the project directory is not available",
            "the project directory must be a directory and must not be a symbolic link",
        )?;
        let current = read_bounded_source_file(
            &path,
            "project.migrate.source_missing",
            relative_path,
            AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
        )?;
        if current != *original {
            return Err(migration_concurrent_change_diagnostic(relative_path));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            migration_write_diagnostic("project.migrate.write_failed", relative_path)
        })?;
        if !migration_target_permissions_are_safe(&metadata) {
            return Err(migration_write_diagnostic(
                "project.migrate.permissions_invalid",
                relative_path,
            ));
        }
        let transaction_directory = parent.join(format!(
            ".registry-serverctl-migrate-{}-{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        targets.push(MigrationWriteTarget {
            relative_path: relative_path.clone(),
            path,
            parent,
            original: original.clone(),
            updated: updated.clone(),
            metadata,
            staged_path: transaction_directory.join("staged"),
            backup_path: transaction_directory.join("original"),
            transaction_directory,
        });
    }

    #[cfg(test)]
    if let MigrationWriteFault::ConcurrentChange(index) = _fault {
        if let Some(target) = targets.get(index) {
            fs::write(&target.path, b"concurrent author edit\n").expect("fault injection writes");
        }
    }

    let stage_result = (|| {
        for (index, target) in targets.iter().enumerate() {
            #[cfg(not(test))]
            let _ = index;
            #[cfg(test)]
            if matches!(_fault, MigrationWriteFault::Stage(failed) if failed == index) {
                return Err(migration_write_diagnostic(
                    "project.migrate.write_failed",
                    &target.relative_path,
                ));
            }
            fs::create_dir(&target.transaction_directory).map_err(|_| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            })?;
            let mut staged = File::options()
                .write(true)
                .create_new(true)
                .open(&target.staged_path)
                .map_err(|_| {
                    migration_write_diagnostic(
                        "project.migrate.write_failed",
                        &target.relative_path,
                    )
                })?;
            staged.write_all(&target.updated).map_err(|_| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            })?;
            fs::set_permissions(&target.staged_path, target.metadata.permissions()).map_err(
                |_| {
                    migration_write_diagnostic(
                        "project.migrate.write_failed",
                        &target.relative_path,
                    )
                },
            )?;
            staged.sync_all().map_err(|_| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            })?;
            sync_directory(&target.transaction_directory).map_err(|_| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            })?;
            sync_directory(&target.parent).map_err(|_| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            })?;
        }
        Ok(())
    })();
    if let Err(error) = stage_result {
        cleanup_migration_transaction(&targets);
        return Err(error);
    }

    // Revalidate every source after staging and before the first rename. This
    // closes the concurrent-edit window without letting one file advance while
    // another is stale.
    let revalidation = targets.iter().try_for_each(|target| {
        let current = read_bounded_source_file(
            &target.path,
            "project.migrate.source_missing",
            &target.relative_path,
            AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
        )
        .map_err(|_| migration_concurrent_change_diagnostic(&target.relative_path))?;
        let metadata = fs::symlink_metadata(&target.path)
            .map_err(|_| migration_concurrent_change_diagnostic(&target.relative_path))?;
        if current == target.original
            && same_file_metadata(&target.metadata, &metadata)
            && same_migration_permissions(&target.metadata, &metadata)
        {
            Ok(())
        } else {
            Err(migration_concurrent_change_diagnostic(
                &target.relative_path,
            ))
        }
    });
    if let Err(error) = revalidation {
        cleanup_migration_transaction(&targets);
        return Err(error);
    }

    let mut backed_up = 0usize;
    for target in &targets {
        if fs::rename(&target.path, &target.backup_path).is_err() {
            let rollback = restore_migration_targets(&targets, backed_up, 0);
            return Err(rollback.unwrap_or_else(|| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            }));
        }
        backed_up += 1;
    }

    let mut promoted = 0usize;
    for (index, target) in targets.iter().enumerate() {
        #[cfg(not(test))]
        let _ = index;
        #[cfg(test)]
        if matches!(_fault, MigrationWriteFault::Commit(failed) if failed == index) {
            let rollback = restore_migration_targets(&targets, backed_up, promoted);
            return Err(rollback.unwrap_or_else(|| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            }));
        }
        if fs::rename(&target.staged_path, &target.path).is_err() {
            let rollback = restore_migration_targets(&targets, backed_up, promoted);
            return Err(rollback.unwrap_or_else(|| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            }));
        }
        promoted += 1;
    }

    for target in &targets {
        if sync_directory(&target.parent).is_err() {
            let rollback = restore_migration_targets(&targets, backed_up, promoted);
            return Err(rollback.unwrap_or_else(|| {
                migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
            }));
        }
    }

    for target in &targets {
        fs::remove_file(&target.backup_path).map_err(|_| {
            migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
        })?;
        fs::remove_dir(&target.transaction_directory).map_err(|_| {
            migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
        })?;
        sync_directory(&target.parent).map_err(|_| {
            migration_write_diagnostic("project.migrate.write_failed", &target.relative_path)
        })?;
    }
    Ok(())
}

fn restore_migration_targets(
    targets: &[MigrationWriteTarget],
    backed_up: usize,
    promoted: usize,
) -> Option<Diagnostic> {
    let mut failed = false;
    for target in targets.iter().take(promoted).rev() {
        if fs::rename(&target.path, &target.staged_path).is_err() {
            // The promoted target contains only the already-fsynced migrated
            // bytes. Removing that exact file is safe when moving it back into
            // staging is unavailable, and lets the original backup be restored
            // on platforms whose rename cannot replace an existing file.
            if fs::remove_file(&target.path).is_err() {
                failed = true;
            }
        }
    }
    for target in targets.iter().take(backed_up).rev() {
        if fs::rename(&target.backup_path, &target.path).is_err() {
            failed = true;
        }
    }
    for target in targets {
        if sync_directory(&target.parent).is_err() {
            failed = true;
        }
    }
    cleanup_migration_transaction(targets);
    failed.then(|| {
        migration_write_diagnostic(
            "project.migrate.rollback_failed",
            targets
                .first()
                .map(|target| target.relative_path.as_str())
                .unwrap_or("project"),
        )
    })
}

fn cleanup_migration_transaction(targets: &[MigrationWriteTarget]) {
    for target in targets {
        let _ = fs::remove_file(&target.staged_path);
        let _ = fs::remove_file(&target.backup_path);
        let _ = fs::remove_dir(&target.transaction_directory);
    }
}

fn migration_write_diagnostic(code: &str, path: &str) -> Diagnostic {
    diagnostic(
        code,
        path,
        "the migrated project source could not be written transactionally",
    )
}

fn migration_concurrent_change_diagnostic(path: &str) -> Diagnostic {
    diagnostic(
        "project.migrate.concurrent_change",
        path,
        "the project source changed after its migration diff was prepared",
    )
}

fn migration_target_permissions_are_safe(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.permissions().readonly()
}

#[cfg(unix)]
fn same_migration_permissions(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    left.permissions().mode() == right.permissions().mode()
}

#[cfg(not(unix))]
fn same_migration_permissions(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.permissions().readonly() == right.permissions().readonly()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

impl ArtifactSelector {
    fn selects(self, path: &str) -> bool {
        match self {
            ArtifactSelector::Openapi => path == "generated/openapi.json",
            ArtifactSelector::Schemas => {
                path.starts_with("generated/schemas/")
                    || path.starts_with("generated/action-schemas/")
            }
            ArtifactSelector::Actions => {
                path == "compiled/actions.json" || path.starts_with("generated/action-schemas/")
            }
            ArtifactSelector::Manifest => path.starts_with("generated/manifest/"),
            ArtifactSelector::Metadata => path == "generated/metadata/registry.json",
            ArtifactSelector::Sql => path == "generated/postgres/schema.sql",
        }
    }

    fn name(self) -> String {
        self.to_possible_value()
            .expect("artifact selections are visible")
            .get_name()
            .to_owned()
    }
}

fn selected_artifacts(
    artifacts: &GeneratedArtifacts,
    selector: ArtifactSelector,
) -> Result<Vec<GeneratedArtifact>, Diagnostic> {
    let selected: Vec<_> = artifacts
        .entries()
        .values()
        .filter(|artifact| selector.selects(&artifact.path))
        .cloned()
        .collect();
    if selected.is_empty() {
        let available = ArtifactSelector::value_variants()
            .iter()
            .filter(|candidate| {
                artifacts
                    .entries()
                    .values()
                    .any(|artifact| candidate.selects(&artifact.path))
            })
            .map(|candidate| candidate.name())
            .collect::<Vec<_>>();
        let available = if available.is_empty() {
            "none".to_owned()
        } else {
            available.join(", ")
        };
        return Err(diagnostic(
            "artifact.selection.empty",
            "artifacts",
            &format!(
                "this compiled project produces no {} artifact; it produces: {available}",
                selector.name()
            ),
        ));
    }
    Ok(selected)
}

fn artifact_report(path: &str, media_type: &str, bytes: &[u8]) -> ArtifactReport {
    use sha2::{Digest, Sha256};

    ArtifactReport {
        path: path.to_owned(),
        media_type: media_type.to_owned(),
        sha256: hex_lower(&Sha256::digest(bytes)),
        byte_length: bytes.len(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn explain_model(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    serde_json::to_value(json!({
        "registryId": compiled.registry_id(),
        "version": compiled.version(),
        "moduleOrder": compiled.module_order(),
        "moduleClosure": compiled.module_closure(),
        "entities": compiled.entities(),
        "physicalNames": compiled.physical_names(),
        "package": compiled.package(),
        "manifestProjection": compiled.manifest_projection(),
    }))
}

fn explain_change_requests(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    let requests = compiled
        .entities()
        .values()
        .filter_map(|entity| {
            let request = entity.change_request.as_ref()?;
            Some(json!({
                "requestEntity": entity.id,
                "requestRoute": entity.route,
                "contractFingerprint": request.contract_fingerprint,
                "bounds": {
                    "maximumTargets": request.maximum_targets,
                    "maximumFieldMutations": request.maximum_field_mutations,
                    "maximumSnapshotBytes": request.maximum_snapshot_bytes,
                },
                "planner": explain_change_request_planner(compiled, entity, request),
                "reviewMode": match request.review_mode {
                    registry_server::model::CompiledChangeRequestReviewMode::None => "none",
                    registry_server::model::CompiledChangeRequestReviewMode::Stages => "staged",
                },
                "application": explain_change_request_application(&request.application),
                "stages": request.stages.iter().map(|stage| json!({
                    "id": stage.id,
                    "approvals": stage.approvals,
                    "excludeSubmitter": stage.exclude_submitter,
                })).collect::<Vec<_>>(),
                "effects": request.effects.iter().map(|effect| {
                    let target = compiled.entities().get(&effect.target.entity_id);
                    json!({
                        "id": effect.id,
                        "operation": operation_wire_name(effect.operation),
                        "target": {
                            "entity": effect.target.entity_id,
                            "binding": match &effect.target.binding {
                                registry_server::model::CompiledChangeRequestTargetBinding::Existing { from_field } => {
                                    json!({"kind": "existing", "fromField": field_summary(entity, from_field)})
                                }
                                registry_server::model::CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
                                    json!({"kind": "reserved_create", "effect": effect})
                                }
                            },
                        },
                        "fields": effect.mutations.iter().map(|mutation| match mutation {
                            registry_server::model::CompiledChangeRequestMutation::Set { field, value } => json!({
                                "kind": "set",
                                "target": field_summary_optional(target, field),
                                "value": match value {
                                    registry_server::model::CompiledChangeRequestValue::FromField { field } => {
                                        json!({"kind": "from_field", "field": field_summary(entity, field)})
                                    }
                                    registry_server::model::CompiledChangeRequestValue::FromEffect { effect, target_entity_id } => {
                                        json!({"kind": "from_effect", "effect": effect, "targetEntity": target_entity_id})
                                    }
                                },
                            }),
                            registry_server::model::CompiledChangeRequestMutation::Clear { field } => json!({
                                "kind": "clear",
                                "target": field_summary_optional(target, field),
                            }),
                        }).collect::<Vec<_>>(),
                        "dependsOn": effect.depends_on.iter().collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "actions": request.actions.iter().map(|action| json!({
                    "operation": operation_wire_name(action.operation.access_operation()),
                    "stage": action.review_stage,
                    "routeId": compiled.routes().routes.iter()
                        .find(|route| route.entity_id == entity.id
                            && route.operation == action.operation.access_operation()
                            && route.request_stage == action.review_stage)
                        .map(|route| route.id.as_str()),
                    "method": "POST",
                    "preconditions": request_action_preconditions(action.operation.access_operation()),
                })).collect::<Vec<_>>(),
                "reviewGrants": request.review_grants.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "stage": grant.stage,
                    "targetEntity": grant.target_entity_id,
                    "readableFields": grant.readable_fields.iter()
                        .map(|field| field_summary_optional(compiled.entities().get(&grant.target_entity_id), field))
                        .collect::<Vec<_>>(),
                    "rowBoundaries": grant.row_boundaries,
                })).collect::<Vec<_>>(),
                "applyGrants": request.apply_grants.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "targetEntity": grant.target_entity_id,
                    "rowBoundaries": grant.row_boundaries,
                })).collect::<Vec<_>>(),
                "presenceGrants": request.presence_grants.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "targetEntity": grant.target_entity_id,
                    "requestRowBoundaries": grant.request_row_boundaries,
                })).collect::<Vec<_>>(),
            }))
        })
        .collect::<Vec<_>>();
    let controlled_writes = compiled
        .entities()
        .values()
        .filter_map(|entity| {
            let control = entity.change_control.as_ref()?;
            let eligible = compiled
                .entities()
                .iter()
                .filter_map(|(request_entity_id, request_entity)| {
                    let request = request_entity.change_request.as_ref()?;
                    let declarative = request
                        .effects
                        .iter()
                        .any(|effect| effect.target.entity_id == entity.id);
                    let planned = request.planner.as_ref().is_some_and(|planner| {
                        planner
                            .writes
                            .iter()
                            .any(|write| write.target_entity_id == entity.id)
                    });
                    (declarative || planned).then_some(request_entity_id.clone())
                })
                .collect::<Vec<_>>();
            Some(json!({
                "entity": entity.id,
                "route": entity.route,
                "requiredFor": control.required_for.iter().map(|operation| operation_wire_name(*operation)).collect::<Vec<_>>(),
                "eligibleRequestTypes": eligible,
                "directWriteRestriction": "controlled operations are absent from ordinary grants and require compiled apply_request context",
            }))
        })
        .collect::<Vec<_>>();
    serde_json::to_value(json!({
        "requests": requests,
        "controlledWrites": controlled_writes,
    }))
}

fn explain_change_request_planner(
    compiled: &CompiledRegistry,
    request_entity: &registry_server::model::CompiledEntity,
    request: &registry_server::model::CompiledChangeRequest,
) -> Value {
    let Some(planner) = request.planner.as_ref() else {
        return json!({
            "kind": "declarative",
            "abi": registry_server::contract::CHANGE_REQUEST_PLAN_ABI_V1,
        });
    };
    json!({
        "kind": "rhai",
        "abi": planner.abi,
        "rhaiVersion": planner.rhai_version,
        "scriptSha256": planner.script_sha256,
        "declaringOrigin": match &planner.source_module {
            Some(module) => json!({"kind": "module", "id": module}),
            None => json!({"kind": "project"}),
        },
        "requestFields": planner.request_fields.iter()
            .map(|field| field_summary(request_entity, field))
            .collect::<Vec<_>>(),
        "limits": {
            "maximumTargets": request.maximum_targets,
            "maximumFieldMutations": request.maximum_field_mutations,
            "maximumSnapshotBytes": request.maximum_snapshot_bytes,
            "maximumSourceBytes": planner.limits.maximum_source_bytes,
            "maximumOperations": planner.limits.maximum_operations,
            "maximumCallDepth": planner.limits.maximum_call_depth,
            "maximumExpressionDepth": planner.limits.maximum_expression_depth,
            "maximumStringBytes": planner.limits.maximum_string_bytes,
            "maximumArrayItems": planner.limits.maximum_array_items,
            "maximumMapEntries": planner.limits.maximum_map_entries,
            "maximumModules": planner.limits.maximum_modules,
        },
        "possibleWrites": planner.writes.iter().map(|write| {
            let target = compiled.entities().get(&write.target_entity_id);
            json!({
                "target": match &write.target_from_field {
                    Some(field) => json!({
                        "kind": "existing",
                        "entity": write.target_entity_id,
                        "fromField": field_summary(request_entity, field),
                    }),
                    None => json!({
                        "kind": "reserved_create",
                        "entity": write.target_entity_id,
                    }),
                },
                "operation": operation_wire_name(write.operation),
                "fields": write.fields.iter()
                    .map(|field| field_summary_optional(target, field))
                    .collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

fn explain_change_request_application(
    application: &registry_server::model::CompiledChangeRequestApplication,
) -> Value {
    let mode = match application.mode {
        registry_server::model::CompiledChangeRequestApplicationMode::Manual => "manual",
        registry_server::model::CompiledChangeRequestApplicationMode::Automatic => "automatic",
        registry_server::model::CompiledChangeRequestApplicationMode::Planner => "planner",
    };
    let allowed_dispositions = match application.mode {
        registry_server::model::CompiledChangeRequestApplicationMode::Manual => vec!["queue"],
        registry_server::model::CompiledChangeRequestApplicationMode::Automatic => vec!["apply"],
        registry_server::model::CompiledChangeRequestApplicationMode::Planner => application
            .allowed_dispositions
            .iter()
            .map(|disposition| match disposition {
                registry_server::model::CompiledChangeRequestDisposition::Apply => "apply",
                registry_server::model::CompiledChangeRequestDisposition::Queue => "queue",
            })
            .collect::<Vec<_>>(),
    };
    json!({
        "mode": mode,
        "allowedDispositions": allowed_dispositions,
        "queueReasons": application.queue_reasons.iter()
            .map(|(code, label)| json!({"code": code, "label": label}))
            .collect::<Vec<_>>(),
    })
}

fn explain_routes(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(compiled.routes())?;
    if compiled.actions().routes.is_empty() {
        return Ok(value);
    }
    let routes = value
        .get_mut("routes")
        .and_then(Value::as_array_mut)
        .expect("compiled routes serialize with a routes array");
    routes.extend(compiled.actions().routes.iter().map(|route| {
        json!({
            "id": route.id,
            "actionId": route.action_id,
            "actionRouteKind": action_route_kind_wire_name(route.kind),
            "method": route.method,
            "path": route.path,
            "operation": operation_wire_name(route.operation),
            "accessProfiles": route.access_profiles,
            "defaultAccessProfile": route.default_access_profile,
            "requiresIdempotencyKey": route.kind == registry_server::model::ActionRouteKind::Invoke,
        })
    }));
    Ok(value)
}

fn explain_actions(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    let actions = compiled
        .actions()
        .actions
        .iter()
        .map(|action| {
            let routes = compiled
                .actions()
                .routes
                .iter()
                .filter(|route| route.action_id == action.id)
                .map(|route| {
                    json!({
                        "id": route.id,
                        "kind": action_route_kind_wire_name(route.kind),
                        "method": "POST",
                        "path": route.path,
                        "operation": operation_wire_name(route.operation),
                        "accessProfiles": route.access_profiles,
                        "defaultAccessProfile": route.default_access_profile,
                        "requiresIdempotencyKey": route.kind == registry_server::model::ActionRouteKind::Invoke,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "id": action.id,
                "sourceModule": action.source_module,
                "contractFingerprint": action.contract_fingerprint,
                "routes": routes,
                "inputs": action.inputs.iter().map(action_input_summary).collect::<Vec<_>>(),
                "effects": action.effects.iter().map(|effect| {
                    let target_entity = compiled.entities().get(&effect.target.entity_id);
                    json!({
                        "id": effect.id,
                        "operation": operation_wire_name(effect.operation),
                        "target": action_target_summary(effect),
                        "fields": effect.mutations.iter().map(|mutation| match mutation {
                            registry_server::model::CompiledActionMutation::Set { field, value } => json!({
                                "kind": "set",
                                "target": field_summary_optional(target_entity, field),
                                "value": match value {
                                    registry_server::model::CompiledActionValue::FromInput { input } => {
                                        json!({"kind": "from_input", "input": action_input_identity(action, input)})
                                    }
                                    registry_server::model::CompiledActionValue::FromEffect { effect, target_entity_id } => {
                                        json!({"kind": "from_effect", "effect": effect, "targetEntity": target_entity_id})
                                    }
                                },
                            }),
                            registry_server::model::CompiledActionMutation::Clear { field } => json!({
                                "kind": "clear",
                                "target": field_summary_optional(target_entity, field),
                            }),
                        }).collect::<Vec<_>>(),
                        "dependsOn": effect.depends_on.iter().collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "targets": action.target_uses.iter().map(|target| json!({
                    "entity": target.entity_id,
                    "operation": operation_wire_name(target.operation),
                    "fields": target.fields.iter()
                        .map(|field| field_summary_optional(compiled.entities().get(&target.entity_id), field))
                        .collect::<Vec<_>>(),
                    "source": match &target.source {
                        registry_server::model::CompiledActionTargetUseSource::Effect { effect } => {
                            json!({"kind": "effect", "effect": effect})
                        }
                        registry_server::model::CompiledActionTargetUseSource::Input { input } => {
                            json!({"kind": "input", "input": action_input_identity(action, input)})
                        }
                    },
                    "conditionRequired": target.condition_required,
                })).collect::<Vec<_>>(),
                "requiredConditionKeys": action.target_uses.iter()
                    .filter(|target| target.condition_required)
                    .filter_map(|target| match &target.source {
                        registry_server::model::CompiledActionTargetUseSource::Input { input } => {
                            action.inputs.iter().find(|candidate| candidate.id == *input)
                        }
                        registry_server::model::CompiledActionTargetUseSource::Effect { .. } => None,
                    })
                    .map(|input| input.api_name.as_str())
                    .collect::<BTreeSet<_>>(),
                "grants": action.grants.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "default": grant.default,
                    "anonymous": grant.anonymous,
                    "requiredScopes": grant.required_scopes,
                    "requiredPurposes": grant.required_purposes,
                    "operations": grant.operations.iter().map(|operation| operation_wire_name(*operation)).collect::<Vec<_>>(),
                    "targets": grant.targets.iter().map(|target| json!({
                        "entity": target.entity_id,
                        "rowBoundaries": target.row_boundaries,
                    })).collect::<Vec<_>>(),
                    "results": grant.results,
                })).collect::<Vec<_>>(),
                "results": action.effects.iter()
                    .filter(|effect| action.result_effects.contains(&effect.id))
                    .map(|effect| json!({
                        "effect": effect.id,
                        "entity": effect.target.entity_id,
                        "operation": operation_wire_name(effect.operation),
                    }))
                    .collect::<Vec<_>>(),
                "bounds": {
                    "maximumTargets": action.maximum_targets,
                    "maximumFieldMutations": action.maximum_field_mutations,
                    "maximumSnapshotBytes": action.maximum_snapshot_bytes,
                }
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_value(json!({ "actions": actions }))
}

fn explain_queries(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    let operations = compiled
        .queries()
        .operations
        .iter()
        .map(|operation| {
            let entity = compiled.entities().get(&operation.entity_id);
            let api_fields = entity
                .map(|entity| {
                    operation
                        .projection_fields
                        .iter()
                        .filter_map(|field_id| {
                            query_field_summary(field_id, query_field_identity(entity, field_id))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let filterable = entity
                .map(|entity| {
                    operation
                        .filter_fields
                        .iter()
                        .filter_map(|field| {
                            let identity = query_field_summary(
                                &field.field,
                                query_field_identity(entity, &field.field),
                            )?;
                            Some(json!({
                                "apiName": identity["apiName"],
                                "field": &field.field,
                                "fieldType": identity["fieldType"],
                                "operators": &field.operators,
                                "wireOperators": wire_filter_operators(&field.operators),
                                "examples": filter_examples(
                                    identity["apiName"].as_str().expect("api name is a string"),
                                    query_field_identity(entity, &field.field)
                                        .expect("field identity was already resolved")
                                        .field_type,
                                    &field.operators,
                                ),
                            }))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let sortable = entity
                .map(|entity| {
                    operation
                        .sort_fields
                        .iter()
                        .filter_map(|field| {
                            let identity = query_field_summary(
                                &field.field,
                                query_field_identity(entity, &field.field),
                            )?;
                            Some(json!({
                                "apiName": identity["apiName"],
                                "field": &field.field,
                                "fieldType": identity["fieldType"],
                                "directions": &field.directions,
                                "examples": [format!("$orderby={}", identity["apiName"].as_str().expect("api name is a string"))],
                            }))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let selectors = entity
                .map(|entity| {
                    operation
                        .selector_fields
                        .iter()
                        .filter_map(|field| {
                            query_field_summary(field, query_field_identity(entity, field))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let mut rendered = json!({
                "id": operation.id,
                "routeId": operation.route_id,
                "profile": operation.profile_id,
                "entity": operation.entity_id,
                "kind": operation.kind,
                "apiFields": api_fields,
                "filterable": filterable,
                "sortable": sortable,
                "allowCount": operation.allow_count,
                "selectors": selectors,
                "readPath": operation.read_path,
                "wire": {
                    "select": "$select",
                    "filter": "$filter",
                    "orderBy": "$orderby",
                    "pageSize": "$top",
                    "count": "$count",
                    "cursor": "$skiptoken",
                    "accessProfile": "accessProfile",
                    "asOf": "asOf",
                },
                "bounds": {
                    "maxPageSize": operation.max_page_size,
                    "maxTop": registry_server::query::MAX_TOP,
                    "maxSelectedFields": registry_server::query::MAX_SELECTED_FIELDS,
                    "maxFilterPayloadBytes": registry_server::query::MAX_QUERY_PAYLOAD_BYTES,
                    "maxFilterDepth": registry_server::query::MAX_FILTER_DEPTH,
                    "maxFilterNodes": registry_server::query::MAX_FILTER_NODES,
                    "maxFilterPredicates": registry_server::query::MAX_FILTER_PREDICATES,
                    "maxInValues": registry_server::query::MAX_IN_VALUES,
                }
            });
            if let Some(bbox) = operation.spatial.as_ref().and_then(|spatial| spatial.bbox.as_ref()) {
                let api_name = entity
                    .and_then(|entity| query_field_identity(entity, &bbox.geometry_field))
                    .map(|identity| identity.api_name)
                    .unwrap_or(&bbox.geometry_field);
                rendered["spatialQueries"] = json!({"bbox": {
                    "field": bbox.geometry_field,
                    "apiName": api_name,
                    "maximumLongitudeSpanDegrees": bbox.maximum_longitude_span_degrees,
                    "maximumLatitudeSpanDegrees": bbox.maximum_latitude_span_degrees,
                    "coordinateReferenceSystem": "CRS84",
                    "requiresPostgis": true
                }});
                rendered["wire"]["bbox"] = json!("bbox");
                if let Some(collection_id) = operation.gis_collection_id() {
                    rendered["gis"] = json!({
                        "collectionId": collection_id,
                        "collectionPath": format!("/v1/gis/collections/{collection_id}"),
                        "itemsPath": format!("/v1/gis/collections/{collection_id}/items"),
                        "accessProfile": operation.profile_id,
                        "representation": "application/geo+json"
                    });
                }
            }
            rendered
        })
        .collect::<Vec<_>>();
    serde_json::to_value(json!({ "operations": operations }))
}

fn query_field_identity<'a>(
    entity: &'a registry_server::model::CompiledEntity,
    field_id: &str,
) -> Option<QueryFieldIdentity<'a>> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| QueryFieldIdentity {
            api_name: &field.logical.api_name,
            source_kind: "stored",
            field_type: &field.logical.field_type,
        })
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| QueryFieldIdentity {
                    api_name: &field.logical.api_name,
                    source_kind: "derived",
                    field_type: &field.logical.field_type,
                })
        })
}

fn field_summary(entity: &registry_server::model::CompiledEntity, field_id: &str) -> Value {
    field_summary_optional(Some(entity), field_id)
}

fn field_summary_optional(
    entity: Option<&registry_server::model::CompiledEntity>,
    field_id: &str,
) -> Value {
    let api_name = entity
        .and_then(|entity| field_api_name(entity, field_id))
        .unwrap_or(field_id);
    json!({
        "field": field_id,
        "apiName": api_name,
    })
}

fn field_api_name<'a>(
    entity: &'a registry_server::model::CompiledEntity,
    field_id: &str,
) -> Option<&'a str> {
    entity
        .stored_fields
        .iter()
        .find(|field| field.logical.id == field_id)
        .map(|field| field.logical.api_name.as_str())
        .or_else(|| {
            entity
                .derived_fields
                .get(field_id)
                .map(|field| field.logical.api_name.as_str())
        })
        .or_else(|| {
            (entity.canonical_id.id == field_id).then_some(entity.canonical_id.api_name.as_str())
        })
}

fn action_input_summary(input: &registry_server::model::CompiledActionInput) -> Value {
    json!({
        "input": input.id,
        "apiName": input.api_name,
        "fieldType": input.field_type,
        "required": input.required,
        "classification": input.classification,
    })
}

fn action_input_identity(action: &registry_server::model::CompiledAction, input_id: &str) -> Value {
    action
        .inputs
        .iter()
        .find(|input| input.id == input_id)
        .map(action_input_summary)
        .unwrap_or_else(|| json!({"input": input_id}))
}

fn action_target_summary(effect: &registry_server::model::CompiledActionEffect) -> Value {
    match &effect.target.binding {
        registry_server::model::CompiledActionTargetBinding::Create => json!({
            "entity": effect.target.entity_id,
            "binding": {"kind": "create"},
        }),
        registry_server::model::CompiledActionTargetBinding::Existing { input } => json!({
            "entity": effect.target.entity_id,
            "binding": {
                "kind": "existing",
                "input": input,
            },
        }),
    }
}

fn action_route_kind_wire_name(kind: registry_server::model::ActionRouteKind) -> &'static str {
    match kind {
        registry_server::model::ActionRouteKind::Invoke => "invoke",
        registry_server::model::ActionRouteKind::TargetConditions => "target_conditions",
    }
}

fn request_action_preconditions(
    operation: registry_server::contract::Operation,
) -> Vec<&'static str> {
    let mut preconditions = vec!["Idempotency-Key", "If-Match"];
    if matches!(
        operation,
        registry_server::contract::Operation::ApproveRequest
            | registry_server::contract::Operation::RejectRequest
            | registry_server::contract::Operation::RequestRevision
            | registry_server::contract::Operation::ApplyRequest
    ) {
        preconditions.push("proposalVersion");
        preconditions.push("effectDigest");
    }
    preconditions
}

fn operation_wire_name(operation: registry_server::contract::Operation) -> &'static str {
    match operation {
        registry_server::contract::Operation::Create => "create",
        registry_server::contract::Operation::Get => "get",
        registry_server::contract::Operation::Lookup => "lookup",
        registry_server::contract::Operation::List => "list",
        registry_server::contract::Operation::Patch => "patch",
        registry_server::contract::Operation::Tombstone => "tombstone",
        registry_server::contract::Operation::Batch => "batch",
        registry_server::contract::Operation::Revisions => "revisions",
        registry_server::contract::Operation::SubmitRequest => "submit_request",
        registry_server::contract::Operation::ApproveRequest => "approve_request",
        registry_server::contract::Operation::RejectRequest => "reject_request",
        registry_server::contract::Operation::RequestRevision => "request_revision",
        registry_server::contract::Operation::ReviseRequest => "revise_request",
        registry_server::contract::Operation::CancelRequest => "cancel_request",
        registry_server::contract::Operation::ApplyRequest => "apply_request",
        registry_server::contract::Operation::Invoke => "invoke",
        registry_server::contract::Operation::Snapshot => "snapshot",
    }
}

struct QueryFieldIdentity<'a> {
    api_name: &'a str,
    source_kind: &'static str,
    field_type: &'a FieldTypeSource,
}

fn query_field_summary(field_id: &str, resolved: Option<QueryFieldIdentity<'_>>) -> Option<Value> {
    let resolved = resolved?;
    Some(json!({
        "field": field_id,
        "apiName": resolved.api_name,
        "sourceKind": resolved.source_kind,
        "fieldType": resolved.field_type,
    }))
}

fn wire_filter_operators(
    operators: &[registry_server::model::CompiledQueryFilterOperator],
) -> Vec<&'static str> {
    let mut wire = BTreeSet::new();
    for operator in operators {
        match operator {
            registry_server::model::CompiledQueryFilterOperator::Equals => {
                wire.insert("eq");
                wire.insert("ne");
            }
            registry_server::model::CompiledQueryFilterOperator::In => {
                wire.insert("in");
            }
            registry_server::model::CompiledQueryFilterOperator::Range => {
                wire.insert("ge");
                wire.insert("gt");
                wire.insert("le");
                wire.insert("lt");
            }
            registry_server::model::CompiledQueryFilterOperator::IsNull => {
                wire.insert("eq null");
            }
            registry_server::model::CompiledQueryFilterOperator::IsNotNull => {
                wire.insert("ne null");
            }
            registry_server::model::CompiledQueryFilterOperator::Prefix => {
                wire.insert("startswith");
            }
            registry_server::model::CompiledQueryFilterOperator::Contains => {
                wire.insert("contains");
            }
        }
    }
    wire.into_iter().collect()
}

fn filter_examples(
    api_name: &str,
    field_type: &FieldTypeSource,
    operators: &[registry_server::model::CompiledQueryFilterOperator],
) -> Vec<String> {
    operators
        .iter()
        .filter_map(|operator| filter_example(api_name, field_type, *operator))
        .collect()
}

fn filter_example(
    api_name: &str,
    field_type: &FieldTypeSource,
    operator: registry_server::model::CompiledQueryFilterOperator,
) -> Option<String> {
    match operator {
        registry_server::model::CompiledQueryFilterOperator::Equals => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter={api_name} eq {first}"))
        }
        registry_server::model::CompiledQueryFilterOperator::In => {
            let first = filter_literal(field_type)?;
            let second = alternate_filter_literal(field_type)?;
            Some(format!("$filter={api_name} in ({first},{second})"))
        }
        registry_server::model::CompiledQueryFilterOperator::Range => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter={api_name} ge {first}"))
        }
        registry_server::model::CompiledQueryFilterOperator::IsNull => {
            Some(format!("$filter={api_name} eq null"))
        }
        registry_server::model::CompiledQueryFilterOperator::IsNotNull => {
            Some(format!("$filter={api_name} ne null"))
        }
        registry_server::model::CompiledQueryFilterOperator::Prefix => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter=startswith({api_name},{first})"))
        }
        registry_server::model::CompiledQueryFilterOperator::Contains => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter=contains({api_name},{first})"))
        }
    }
}

fn filter_literal(field_type: &FieldTypeSource) -> Option<String> {
    match field_type {
        FieldTypeSource::Boolean => Some("true".to_owned()),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => quoted_example_string(*min_length, *max_length),
        FieldTypeSource::Text { max_length } => quoted_example_string(0, *max_length),
        FieldTypeSource::Int64 => Some("1".to_owned()),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => decimal_example_literal(*precision, *scale, minimum.as_deref(), maximum.as_deref()),
        FieldTypeSource::Date => Some("'2026-01-02'".to_owned()),
        FieldTypeSource::Timestamp => Some("'2026-01-02T03:04:05Z'".to_owned()),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            Some("'00000000-0000-4000-8000-000000000000'".to_owned())
        }
        FieldTypeSource::VocabularyCode { values, .. } => {
            values.first().map(|value| quote_filter_string(value))
        }
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => None,
    }
}

fn alternate_filter_literal(field_type: &FieldTypeSource) -> Option<String> {
    match field_type {
        FieldTypeSource::Boolean => Some("false".to_owned()),
        FieldTypeSource::String {
            min_length,
            max_length,
        } => quoted_alternate_string(*min_length, *max_length),
        FieldTypeSource::Text { max_length } => quoted_alternate_string(0, *max_length),
        FieldTypeSource::Int64 => Some("2".to_owned()),
        FieldTypeSource::Decimal {
            precision,
            scale,
            minimum,
            maximum,
        } => decimal_alternate_literal(*precision, *scale, minimum.as_deref(), maximum.as_deref()),
        FieldTypeSource::Date => Some("'2026-01-03'".to_owned()),
        FieldTypeSource::Timestamp => Some("'2026-01-02T03:04:06Z'".to_owned()),
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
            Some("'00000000-0000-4000-8000-000000000001'".to_owned())
        }
        FieldTypeSource::VocabularyCode { values, .. } => {
            values.get(1).map(|value| quote_filter_string(value))
        }
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => None,
    }
}

fn quoted_example_string(min_length: u32, max_length: u32) -> Option<String> {
    if max_length == 0 {
        return Some("''".to_owned());
    }
    if min_length <= 7 && max_length >= 7 {
        return Some("'example'".to_owned());
    }
    let length = usize::try_from(min_length.max(1).min(max_length)).ok()?;
    Some(quote_filter_string(&"a".repeat(length)))
}

fn quoted_alternate_string(min_length: u32, max_length: u32) -> Option<String> {
    if min_length <= 6 && max_length >= 6 {
        return Some("'sample'".to_owned());
    }
    if max_length == 0 {
        return None;
    }
    let length = usize::try_from(min_length.max(1).min(max_length)).ok()?;
    Some(quote_filter_string(&"b".repeat(length)))
}

fn quote_filter_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn decimal_example_literal(
    precision: u8,
    scale: u8,
    minimum: Option<&str>,
    maximum: Option<&str>,
) -> Option<String> {
    if let Some(minimum) = minimum {
        return Some(minimum.to_owned());
    }
    let zero = zero_decimal_literal(precision, scale)?;
    match maximum {
        Some(maximum)
            if decimal_literal_order(maximum, &zero) == Some(std::cmp::Ordering::Less) =>
        {
            Some(maximum.to_owned())
        }
        _ => Some(zero),
    }
}

fn decimal_alternate_literal(
    precision: u8,
    scale: u8,
    minimum: Option<&str>,
    maximum: Option<&str>,
) -> Option<String> {
    let first = decimal_example_literal(precision, scale, minimum, maximum)?;
    let candidate = decimal_one_literal(precision, scale)?;
    if Some(std::cmp::Ordering::Greater) == decimal_literal_order(&candidate, &first)
        && maximum.is_none_or(|maximum| {
            decimal_literal_order(&candidate, maximum) != Some(std::cmp::Ordering::Greater)
        })
    {
        return Some(candidate);
    }
    None
}

fn zero_decimal_literal(precision: u8, scale: u8) -> Option<String> {
    if !(1..=38).contains(&precision) || scale > precision {
        return None;
    }
    Some(if scale == 0 {
        "0".to_owned()
    } else {
        format!("0.{}", "0".repeat(usize::from(scale)))
    })
}

fn decimal_one_literal(precision: u8, scale: u8) -> Option<String> {
    if !(1..=38).contains(&precision) || scale > precision || precision == scale {
        return None;
    }
    Some(if scale == 0 {
        "1".to_owned()
    } else {
        format!("1.{}", "0".repeat(usize::from(scale)))
    })
}

fn decimal_literal_order(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = left.parse::<f64>().ok()?;
    let right = right.parse::<f64>().ok()?;
    left.partial_cmp(&right)
}

fn validate_project_directory(project_path: &Path) -> Result<(), Diagnostic> {
    if project_path.as_os_str().is_empty() || has_parent_component(project_path) {
        return Err(diagnostic(
            "source.project.path_unsafe",
            "project",
            "the project path must not contain parent-directory components",
        ));
    }
    validate_directory(project_path, "source.project.invalid")
}

fn validate_directory(path: &Path, code: &str) -> Result<(), Diagnostic> {
    validate_directory_for(
        path,
        code,
        "project",
        "the project directory is not available",
        "the project directory must be a directory and must not be a symbolic link",
    )
}

fn validate_directory_for(
    path: &Path,
    code: &str,
    report_path: &str,
    unavailable_message: &str,
    invalid_message: &str,
) -> Result<(), Diagnostic> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| diagnostic(code, report_path, unavailable_message))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(diagnostic(code, report_path, invalid_message));
    }
    ensure_no_symlink_components(path, code, report_path)
}

/// Read a bounded regular file whose diagnostics address the project closure as
/// a whole, for callers that report their own file-addressed refusal.
fn read_bounded_regular_file(
    path: &Path,
    missing_code: &str,
    bound: u64,
) -> Result<Vec<u8>, Diagnostic> {
    read_bounded_source_file(path, missing_code, "project", bound)
}

/// Read a bounded regular file and address every refusal at `report_path`, the
/// project-relative name of the file being read.
fn read_bounded_source_file(
    path: &Path,
    missing_code: &str,
    report_path: &str,
    bound: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        diagnostic(
            missing_code,
            report_path,
            "the required authoring source is not available",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(diagnostic(
            "source.file.invalid",
            report_path,
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    ensure_no_symlink_components(path, "source.file.invalid", report_path)?;
    if metadata.len() > bound {
        return Err(diagnostic(
            "source.file.bounds",
            report_path,
            "an authoring source exceeds its fixed size bound",
        ));
    }
    let file = File::open(path).map_err(|_| {
        diagnostic(
            "source.file.unreadable",
            report_path,
            "an authoring source cannot be read",
        )
    })?;
    let opened = file.metadata().map_err(|_| {
        diagnostic(
            "source.file.unreadable",
            report_path,
            "an authoring source cannot be read",
        )
    })?;
    let after = fs::symlink_metadata(path).map_err(|_| {
        diagnostic(
            "source.file.invalid",
            report_path,
            "authoring sources must be regular files and must not be symbolic links",
        )
    })?;
    if after.file_type().is_symlink()
        || !opened.is_file()
        || !same_file_metadata(&metadata, &opened)
        || !same_file_metadata(&opened, &after)
    {
        return Err(diagnostic(
            "source.file.invalid",
            report_path,
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    if opened.len() > bound {
        return Err(diagnostic(
            "source.file.bounds",
            report_path,
            "an authoring source exceeds its fixed size bound",
        ));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| {
        diagnostic(
            "source.file.bounds",
            report_path,
            "an authoring source exceeds its fixed size bound",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| {
            diagnostic(
                "source.file.unreadable",
                report_path,
                "an authoring source cannot be read",
            )
        })?;
    if bytes.len() as u64 > bound || bytes.len() as u64 != opened.len() {
        return Err(diagnostic(
            "source.file.bounds",
            report_path,
            "an authoring source exceeds its fixed size bound",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn write_source_files(output: &Path, files: &BTreeMap<String, Vec<u8>>) -> Result<(), Diagnostic> {
    write_files_with_before_publish(output, files, |_| Ok(()))
}

fn write_artifacts(output: &Path, artifacts: &[GeneratedArtifact]) -> Result<(), Diagnostic> {
    let files = artifacts
        .iter()
        .map(|artifact| (artifact.path.clone(), artifact.bytes.clone()))
        .collect();
    write_files_with_before_publish(output, &files, |_| Ok(()))
}

#[cfg(test)]
fn write_artifacts_with_before_publish(
    output: &Path,
    artifacts: &GeneratedArtifacts,
    before_publish: impl FnOnce(&Path) -> Result<(), Diagnostic>,
) -> Result<(), Diagnostic> {
    let files = artifacts
        .entries()
        .values()
        .map(|artifact| (artifact.path.clone(), artifact.bytes.clone()))
        .collect();
    write_files_with_before_publish(output, &files, before_publish)
}

fn write_files_with_before_publish(
    output: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    before_publish: impl FnOnce(&Path) -> Result<(), Diagnostic>,
) -> Result<(), Diagnostic> {
    if output.as_os_str().is_empty()
        || has_parent_component(output)
        || output.file_name().is_none()
        || output.exists()
    {
        return Err(diagnostic(
            "output.destination.invalid",
            "output",
            "the output directory must be a new path without parent-directory components",
        ));
    }
    // A bare relative destination names a child of the working directory, so its
    // empty parent is that directory.
    let parent = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    validate_directory_for(
        parent,
        "output.parent.invalid",
        "output.parent",
        "the output parent directory is not available; create it, or give a destination inside a directory that exists",
        "the output parent must be a directory and must not be a symbolic link",
    )?;
    ensure_no_symlink_components(output, "output.destination.invalid", "output")?;

    let staged = create_staging_directory(parent)?;
    let result = (|| {
        for (relative_path, bytes) in files {
            let path = safe_artifact_path(&staged, relative_path)?;
            if let Some(directory) = path.parent() {
                fs::create_dir_all(directory).map_err(|_| {
                    diagnostic(
                        "output.write.failed",
                        "output",
                        "a generated artifact could not be written",
                    )
                })?;
            }
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|_| {
                    diagnostic(
                        "output.write.failed",
                        "output",
                        "a generated artifact could not be written",
                    )
                })?;
            file.write_all(bytes).map_err(|_| {
                diagnostic(
                    "output.write.failed",
                    "output",
                    "a generated artifact could not be written",
                )
            })?;
            file.sync_all().map_err(|_| {
                diagnostic(
                    "output.write.failed",
                    "output",
                    "a generated artifact could not be written",
                )
            })?;
        }
        before_publish(output)?;
        publish_staged_directory(&staged, output)
    })();
    if result.is_err() && staged.exists() {
        let _ = fs::remove_dir_all(&staged);
    }
    result
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn publish_staged_directory(staged: &Path, output: &Path) -> Result<(), Diagnostic> {
    use rustix::fs::{renameat_with, RenameFlags, CWD};

    renameat_with(CWD, staged, CWD, output, RenameFlags::NOREPLACE).map_err(|_| {
        diagnostic(
            "output.publish.failed",
            "output",
            "the generated artifact directory could not be published",
        )
    })
}

#[cfg(target_os = "windows")]
fn publish_staged_directory(staged: &Path, output: &Path) -> Result<(), Diagnostic> {
    fs::rename(staged, output).map_err(|_| {
        diagnostic(
            "output.publish.failed",
            "output",
            "the generated artifact directory could not be published",
        )
    })
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows")))]
fn publish_staged_directory(_staged: &Path, _output: &Path) -> Result<(), Diagnostic> {
    Err(diagnostic(
        "output.publish.unsupported",
        "output",
        "atomic no-replace directory publication is unavailable on this platform",
    ))
}

fn create_staging_directory(parent: &Path) -> Result<PathBuf, Diagnostic> {
    for _ in 0..64 {
        let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staged = parent.join(format!(
            ".registry-serverctl-stage-{}-{counter}",
            std::process::id()
        ));
        match fs::create_dir(&staged) {
            Ok(()) => return Ok(staged),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(diagnostic(
                    "output.stage.failed",
                    "output",
                    "a staged output directory could not be created",
                ));
            }
        }
    }
    Err(diagnostic(
        "output.stage.failed",
        "output",
        "a staged output directory could not be created",
    ))
}

fn safe_artifact_path(root: &Path, artifact_path: &str) -> Result<PathBuf, Diagnostic> {
    let path = Path::new(artifact_path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(diagnostic(
            "artifact.path.invalid",
            "artifacts",
            "the compiler returned an unsafe artifact path",
        ));
    }
    Ok(root.join(path))
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn ensure_no_symlink_components(
    path: &Path,
    code: &str,
    report_path: &str,
) -> Result<(), Diagnostic> {
    let mut checked = if path.is_absolute() {
        PathBuf::from(std::path::MAIN_SEPARATOR_STR)
    } else {
        PathBuf::new()
    };
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                return Err(diagnostic(
                    code,
                    report_path,
                    "paths must not contain parent-directory components",
                ));
            }
            Component::Normal(part) => checked.push(part),
        }
        match fs::symlink_metadata(&checked) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(diagnostic(
                    code,
                    report_path,
                    "paths must not traverse symbolic links",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(diagnostic(
                    code,
                    report_path,
                    "paths cannot be inspected safely",
                ));
            }
        }
    }
    Ok(())
}

fn first_diagnostic(failure: CompileFailure) -> Diagnostic {
    failure.diagnostics().first().cloned().unwrap_or_else(|| {
        diagnostic(
            "source.invalid",
            "project",
            "the authoring source is invalid",
        )
    })
}

fn remap_derived_diagnostic_path(
    mut diagnostic: Diagnostic,
    source: &CapturedProjectSource,
) -> Diagnostic {
    if !diagnostic.code.starts_with("derived.sql.") {
        return diagnostic;
    }
    diagnostic.message =
        "derived SQL asset failed value-minimized validation against its module config".to_owned();
    if let Some(path) = derived_source_path(source, &diagnostic.path) {
        diagnostic.path = path;
    }
    diagnostic
}

fn derived_source_path(source: &CapturedProjectSource, diagnostic_path: &str) -> Option<String> {
    for module in &source.modules {
        for entity in &module.module.entities {
            for derived in &entity.derived {
                let path = format!("entities[{}].derived[{}].sql", entity.id, derived.id);
                if path == diagnostic_path {
                    return Some(format!(
                        "modules/{}/module.yaml:{}",
                        module.id, diagnostic_path
                    ));
                }
            }
        }
        for extension in &module.module.extend_entities {
            for derived in &extension.derived {
                let path = format!("entities[{}].derived[{}].sql", extension.entity, derived.id);
                if path == diagnostic_path {
                    return Some(format!(
                        "modules/{}/module.yaml:{}",
                        module.id, diagnostic_path
                    ));
                }
            }
        }
    }
    None
}

fn tool_diagnostic(
    diagnostic: Diagnostic,
    artifact: DiagnosticArtifact,
    suggested_action: SuggestedAction,
) -> ToolDiagnostic {
    ToolDiagnostic {
        severity: diagnostic.severity,
        code: diagnostic.code,
        artifact,
        path: diagnostic.path,
        message: diagnostic.message,
        suggested_action,
    }
}

fn diagnostic(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

fn write_success(
    report: &SuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "{} succeeded", report.command).and_then(|()| {
            writeln!(stdout, "revision: {}", report.revision)?;
            for finding in &report.findings {
                writeln!(
                    stdout,
                    "finding {} at {}: {}",
                    finding.code, finding.path, finding.message
                )?;
            }
            if !report.artifacts.is_empty() {
                writeln!(stdout, "artifacts: {}", report.artifacts.len())?;
            }
            if let Some(explanation) = &report.explanation {
                if explanation.get("scopeMatching").is_some()
                    || explanation.get("mode").and_then(Value::as_str) == Some("offline_synthetic")
                {
                    return write_access_explanation(explanation, stdout);
                }
                let rendered =
                    serde_json::to_string_pretty(explanation).map_err(io::Error::other)?;
                writeln!(stdout, "{rendered}")?;
            }
            Ok(())
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_project_migrate_success(
    report: &ProjectMigrateSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else if !report.changed {
        writeln!(
            stdout,
            "project migrate: already uses the plural authoring model"
        )
    } else {
        writeln!(
            stdout,
            "project migrate: {}",
            if report.written {
                "wrote the reviewed migration"
            } else {
                "dry run; pass --write to apply this diff"
            }
        )
        .and_then(|()| writeln!(stdout, "{}", report.diff.trim_end()))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_planner_test_success(
    report: &PlannerTestSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_value(report)
            .map_err(io::Error::other)
            .and_then(|value| canonicalize_json(&value).map_err(io::Error::other))
            .and_then(|bytes| stdout.write_all(&bytes))
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "project planner-test succeeded")
            .and_then(|()| writeln!(stdout, "compiled revision: {}", report.compiled_revision))
            .and_then(|()| writeln!(stdout, "request entity: {}", report.request_entity))
            .and_then(|()| writeln!(stdout, "planner kind: {}", report.planner.kind))
            .and_then(|()| writeln!(stdout, "planner ABI: {}", report.planner.abi))
            .and_then(|()| {
                writeln!(
                    stdout,
                    "planner script SHA-256: {}",
                    report.planner.script_sha256
                )
            })
            .and_then(|()| writeln!(stdout, "disposition: {}", report.disposition))
            .and_then(|()| {
                if let Some(reason) = &report.queue_reason {
                    writeln!(stdout, "queue reason: {} ({})", reason.code, reason.label)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                for effect in &report.effects {
                    writeln!(
                        stdout,
                        "effect {}: target={}, operation={}, fields={}, dependencies={}",
                        effect.id,
                        effect.target_kind,
                        effect.operation,
                        effect.fields.join(","),
                        effect.depends_on.join(",")
                    )?;
                }
                writeln!(
                    stdout,
                    "counts: effects={}, field mutations={}, dependencies={}",
                    report.counts.effects,
                    report.counts.field_mutations,
                    report.counts.dependencies
                )
            })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_access_explanation(explanation: &Value, stdout: &mut dyn Write) -> io::Result<()> {
    if explanation.get("mode").and_then(Value::as_str) == Some("offline_synthetic") {
        let admitted = explanation["admitted"].as_bool() == Some(true);
        writeln!(
            stdout,
            "synthetic profile admission: {} ({})",
            if admitted { "allowed" } else { "refused" },
            explanation["reason"].as_str().unwrap_or("unknown")
        )?;
        writeln!(
            stdout,
            "No credentials verified, records checked, or authority issued. Claim values are not printed."
        )?;
        if explanation["effectiveProfile"].is_object() {
            write_access_profile(&explanation["effectiveProfile"], stdout)?;
        }
        return Ok(());
    }
    for key in [
        "scopeMatching",
        "purposeMatching",
        "rowMatching",
        "profileSelection",
    ] {
        writeln!(stdout, "{}", explanation[key].as_str().unwrap_or(""))?;
    }
    if let Some(entities) = explanation["entities"].as_array() {
        for entity in entities {
            writeln!(
                stdout,
                "\nentity: {} ({})",
                entity["entity"].as_str().unwrap_or(""),
                entity["classification"].as_str().unwrap_or("")
            )?;
            if !entity["requirements"].is_null() {
                writeln!(
                    stdout,
                    "  mandatory requirements: {}",
                    entity["requirements"]
                )?;
            }
            if let Some(profiles) = entity["profiles"].as_array() {
                for profile in profiles {
                    write_access_profile(profile, stdout)?;
                }
            }
        }
    }
    Ok(())
}

fn write_access_profile(profile: &Value, stdout: &mut dyn Write) -> io::Result<()> {
    writeln!(
        stdout,
        "  profile: {}",
        profile["id"].as_str().unwrap_or("")
    )?;
    writeln!(
        stdout,
        "    principal claim: {}",
        profile["principalClaim"]
            .as_str()
            .unwrap_or("none (anonymous)")
    )?;
    for (field, label, empty) in [
        ("operations", "operations", "none"),
        ("requiredScopes", "required scopes (all)", "none required"),
        ("requiredPurposes", "allowed purposes (any)", "unrestricted"),
        ("readableFields", "readable fields", "none"),
        ("writableFields", "writable fields", "none"),
        ("filterableFields", "filterable fields", "none"),
        ("sortableFields", "sortable fields", "none"),
        ("rowBoundaries", "row restrictions (all)", "unrestricted"),
        ("lookups", "lookups", "none"),
        ("readPaths", "related records", "none"),
    ] {
        let value = &profile[field];
        if value.is_null() || value.as_array().is_some_and(Vec::is_empty) {
            writeln!(stdout, "    {label}: {empty}")?;
        } else {
            writeln!(stdout, "    {label}: {value}")?;
        }
    }
    for field in [
        "anonymous",
        "allowCount",
        "revisionAccess",
        "allowDataExport",
    ] {
        writeln!(
            stdout,
            "    {field}: {}",
            profile[field].as_bool().unwrap_or(false)
        )?;
    }
    Ok(())
}

fn write_doctor_success(
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let report = DoctorSuccessReport {
        ok: true,
        command: "doctor",
    };
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, &report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "doctor succeeded")
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_verify_success(
    report: &VerifySuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "{} succeeded", report.command).and_then(|()| {
            writeln!(stdout, "assurance: runtime_bound")?;
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "registry id: {}", report.registry.id)?;
            writeln!(stdout, "registry version: {}", report.registry.version)?;
            writeln!(stdout, "registry revision: {}", report.registry.revision)?;
            writeln!(stdout, "modules: {}", report.inventory.modules)?;
            writeln!(stdout, "entities: {}", report.inventory.entities)?;
            writeln!(stdout, "routes: {}", report.inventory.routes)?;
            writeln!(
                stdout,
                "access entries: {}",
                report.inventory.access_entries
            )?;
            writeln!(stdout, "queries: {}", report.inventory.queries)?;
            writeln!(
                stdout,
                "event deliveries: {}",
                report.inventory.event_deliveries
            )?;
            writeln!(
                stdout,
                "DDL statements: {}",
                report.inventory.ddl_statements
            )?;
            writeln!(
                stdout,
                "generated artifacts: {}",
                report.inventory.generated_artifacts
            )
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_package_success(
    report: &PackageSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "package succeeded").and_then(|()| {
            writeln!(stdout, "profile: production")?;
            writeln!(
                stdout,
                "state: {}",
                match report.state {
                    PackageReportState::AwaitingSignatures => "awaiting_signatures",
                    PackageReportState::Published => "published",
                }
            )?;
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(
                stdout,
                "signature threshold: {}",
                report.signature_threshold
            )?;
            writeln!(
                stdout,
                "provided signatures: {}",
                report.provided_signatures
            )?;
            writeln!(stdout, "package files: {}", report.package_files)?;
            writeln!(
                stdout,
                "signing input sha256: {}",
                report.signing_input.sha256
            )?;
            writeln!(
                stdout,
                "signing input bytes: {}",
                report.signing_input.byte_length
            )
        })
    };
    write_result(result, stderr)
}

fn write_schema_test_success(
    report: &SchemaTestSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "test succeeded").and_then(|()| {
            writeln!(stdout, "profile: production")?;
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "schema fingerprint: {}", report.schema_fingerprint)?;
            writeln!(
                stdout,
                "signing input sha256: {}",
                report.signing_input_sha256
            )?;
            writeln!(
                stdout,
                "successful journeys: {}",
                report.successful_journey_ids.join(",")
            )?;
            writeln!(stdout, "receipt sha256: {}", report.receipt.sha256)?;
            writeln!(stdout, "receipt bytes: {}", report.receipt.byte_length)
        })
    };
    write_result(result, stderr)
}

fn write_apply_success(
    report: &ApplySuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "apply succeeded").and_then(|()| {
            writeln!(
                stdout,
                "activation: {}",
                match report.activation {
                    ApplyActivation::Initial => "initial",
                    ApplyActivation::Successor => "successor",
                }
            )?;
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "schema fingerprint: {}", report.schema_fingerprint)?;
            writeln!(stdout, "package sequence: {}", report.package_sequence)
        })
    };
    write_result(result, stderr)
}

fn write_result(result: io::Result<()>, stderr: &mut dyn Write) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_migration_explain_success(
    report: &MigrationExplainSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        write_migration_explain_human(report, stdout)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_migration_reconcile_success(
    report: &MigrationReconcileSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        write_migration_reconcile_human(report, stdout)
    };
    write_result(result, stderr)
}

fn write_migration_reconcile_human(
    report: &MigrationReconcileSuccessReport,
    stdout: &mut dyn Write,
) -> io::Result<()> {
    let outcome = &report.outcome;
    writeln!(stdout, "migration reconcile succeeded")?;
    writeln!(stdout, "outcome: {}", outcome.outcome)?;
    writeln!(stdout, "executed: {}", outcome.executed)?;
    writeln!(
        stdout,
        "maintenance status: {}",
        optional(outcome.maintenance_status.as_deref())
    )?;
    writeln!(
        stdout,
        "pinned target revision: {}",
        optional(outcome.maintenance_target_revision.as_deref())
    )?;
    writeln!(
        stdout,
        "active package revision: {}",
        optional(outcome.active_package_revision.as_deref())
    )?;
    writeln!(
        stdout,
        "presented target revision: {}",
        outcome.target_package_revision
    )?;
    writeln!(
        stdout,
        "target catalog finding: {}",
        optional(outcome.target_catalog_finding)
    )?;
    writeln!(
        stdout,
        "active catalog finding: {}",
        optional(outcome.active_catalog_finding)
    )?;
    writeln!(
        stdout,
        "unresolvable reason: {}",
        optional(outcome.unresolvable_reason)
    )?;
    writeln!(stdout, "plan kind: {}", outcome.plan_kind)?;
    writeln!(stdout, "migration steps: {}", outcome.migration_step_count)?;
    writeln!(
        stdout,
        "reviewed plan closed: {}",
        optional_flag(outcome.reviewed_plan_closed)
    )?;
    writeln!(
        stdout,
        "durable step progress: {}",
        optional_flag(outcome.durable_step_progress)
    )
}

fn optional(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

fn optional_flag(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "none",
    }
}

fn write_history_erase_success(
    report: &HistoryEraseSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "history erase succeeded").and_then(|()| {
            writeln!(
                stdout,
                "package revision: {}",
                report.outcome.package_revision
            )?;
            writeln!(stdout, "coverage ready: {}", report.outcome.coverage_ready)?;
            match report.outcome.unavailable_after_position {
                Some(position) => writeln!(stdout, "unavailable after position: {position}")?,
                None => writeln!(stdout, "unavailable after position: none")?,
            }
            writeln!(
                stdout,
                "affected commits: {}",
                report.outcome.affected_commit_count
            )?;
            writeln!(
                stdout,
                "erased revisions: {}",
                report.outcome.erased_revision_count
            )?;
            writeln!(
                stdout,
                "erased commit members: {}",
                report.outcome.erased_commit_member_count
            )?;
            writeln!(
                stdout,
                "scrubbed change contexts: {}",
                report.outcome.scrubbed_change_context_count
            )?;
            writeln!(
                stdout,
                "scrubbed outbox payloads: {}",
                report.outcome.scrubbed_outbox_payload_count
            )?;
            writeln!(
                stdout,
                "scrubbed cached responses: {}",
                report.outcome.scrubbed_cached_response_count
            )?;
            writeln!(
                stdout,
                "removed descriptors: {}",
                report.outcome.removed_descriptor_count
            )
        })
    };
    write_result(result, stderr)
}

fn write_history_rebaseline_success(
    report: &HistoryRebaselineSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "history rebaseline succeeded").and_then(|()| {
            writeln!(
                stdout,
                "package revision: {}",
                report.outcome.package_revision
            )?;
            writeln!(
                stdout,
                "coverage baseline position: {}",
                report.outcome.baseline_position
            )?;
            writeln!(
                stdout,
                "verified entities: {}",
                report.outcome.verified_entity_count
            )?;
            writeln!(
                stdout,
                "verified records: {}",
                report.outcome.verified_record_count
            )?;
            writeln!(
                stdout,
                "previous coverage baseline position: {}",
                report.outcome.previous_coverage_baseline_position
            )?;
            match report.outcome.previous_unavailable_after_position {
                Some(position) => {
                    writeln!(stdout, "previous unavailable after position: {position}")?
                }
                None => writeln!(stdout, "previous unavailable after position: none")?,
            }
            writeln!(
                stdout,
                "snapshot references before the new baseline remain unavailable"
            )
        })
    };
    write_result(result, stderr)
}

fn write_data_validate_success(
    report: &DataValidateSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "data validate succeeded").and_then(|()| {
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "schema fingerprint: {}", report.schema_fingerprint)?;
            writeln!(stdout, "entity: {}", report.entity_id)?;
            writeln!(stdout, "profile: {}", report.profile_id)?;
            writeln!(
                stdout,
                "operation: {}",
                data_operation_name(report.operation)
            )?;
            writeln!(stdout, "input bytes: {}", report.input_length)?;
            writeln!(stdout, "items: {}", report.item_count)?;
            writeln!(stdout, "chunks: {}", report.chunk_count)?;
            writeln!(stdout, "maximum items: {}", report.maximum_items)?;
            writeln!(stdout, "maximum bytes: {}", report.maximum_bytes)
        })
    };
    write_result(result, stderr)
}

fn write_data_import_success(
    report: &DataImportSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "data import succeeded").and_then(|()| {
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "schema fingerprint: {}", report.schema_fingerprint)?;
            writeln!(stdout, "entity: {}", report.entity_id)?;
            writeln!(stdout, "profile: {}", report.profile_id)?;
            writeln!(
                stdout,
                "operation: {}",
                data_operation_name(report.operation)
            )?;
            writeln!(stdout, "input bytes: {}", report.input_length)?;
            writeln!(stdout, "items: {}", report.item_count)?;
            writeln!(stdout, "completed chunks: {}", report.completed_chunk_count)?;
            writeln!(stdout, "committed items: {}", report.committed_items)?;
            writeln!(stdout, "complete: {}", report.complete)
        })
    };
    write_result(result, stderr)
}

fn write_data_export_success(
    report: &DataExportSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "data export succeeded").and_then(|()| {
            writeln!(stdout, "package revision: {}", report.package_revision)?;
            writeln!(stdout, "schema fingerprint: {}", report.schema_fingerprint)?;
            writeln!(stdout, "entity: {}", report.entity_id)?;
            writeln!(stdout, "profile: {}", report.profile_id)?;
            writeln!(stdout, "fields: {}", report.requested_fields.join(","))?;
            writeln!(stdout, "completed pages: {}", report.completed_page_count)?;
            writeln!(stdout, "records: {}", report.record_count)?;
            writeln!(stdout, "output bytes: {}", report.output_length)?;
            writeln!(stdout, "complete: {}", report.complete)
        })
    };
    write_result(result, stderr)
}

fn write_webhook_sample_success(
    report: &WebhookSampleSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "webhook sample succeeded").and_then(|()| {
            writeln!(stdout, "event: {}", report.outcome.event_id)?;
            writeln!(
                stdout,
                "{} {} HTTP/1.1",
                report.outcome.request.method, report.outcome.request.request_target
            )?;
            for (name, value) in &report.outcome.request.headers {
                writeln!(stdout, "{name}: {value}")?;
            }
            writeln!(stdout)?;
            writeln!(stdout, "{}", report.outcome.request.canonical_body)
        })
    };
    write_result(result, stderr)
}

fn write_webhook_list_success(
    report: &WebhookListSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "webhook list succeeded").and_then(|()| {
            for delivery in &report.outcome.deliveries {
                let rendered = serde_json::to_string(delivery).map_err(io::Error::other)?;
                writeln!(stdout, "delivery: {rendered}")?;
            }
            Ok(())
        })
    };
    write_result(result, stderr)
}

fn write_webhook_replay_success(
    report: &WebhookReplaySuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "webhook replay succeeded").and_then(|()| {
            writeln!(stdout, "event id: {}", report.outcome.event_id)?;
            writeln!(stdout, "delivery id: {}", report.outcome.delivery_id)?;
            writeln!(stdout, "generation: {}", report.outcome.generation)
        })
    };
    write_result(result, stderr)
}

fn write_request_retention_list_success(
    report: &RequestRetentionListSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "request-retention list succeeded").and_then(|()| {
            for item in &report.outcome.page.requests {
                let rendered = serde_json::to_string(item).map_err(io::Error::other)?;
                writeln!(stdout, "request: {rendered}")?;
            }
            if let Some(cursor) = &report.outcome.page.next_cursor {
                writeln!(stdout, "next cursor: {cursor}")?;
            }
            Ok(())
        })
    };
    write_result(result, stderr)
}

fn write_request_retention_dry_run_success(
    report: &RequestRetentionDryRunSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "request-retention dry-run succeeded").and_then(|()| {
            let rendered =
                serde_json::to_string(&report.outcome.dry_run.erasure).map_err(io::Error::other)?;
            writeln!(
                stdout,
                "request entity: {}",
                report.outcome.dry_run.request_entity_id
            )?;
            writeln!(stdout, "request id: {}", report.outcome.dry_run.request_id)?;
            writeln!(
                stdout,
                "proposal version: {}",
                report.outcome.dry_run.proposal_version
            )?;
            writeln!(
                stdout,
                "retention mode: {}",
                report.outcome.dry_run.retention_mode
            )?;
            writeln!(stdout, "pinned: {}", report.outcome.dry_run.pinned)?;
            writeln!(
                stdout,
                "eligible for erasure: {}",
                report.outcome.dry_run.eligible_for_erasure
            )?;
            writeln!(stdout, "erasure: {rendered}")
        })
    };
    write_result(result, stderr)
}

fn write_request_retention_erase_success(
    report: &RequestRetentionEraseSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "request-retention erase succeeded").and_then(|()| {
            let rendered =
                serde_json::to_string(&report.outcome.erase.erasure).map_err(io::Error::other)?;
            writeln!(
                stdout,
                "request entity: {}",
                report.outcome.erase.request_entity_id
            )?;
            writeln!(stdout, "request id: {}", report.outcome.erase.request_id)?;
            writeln!(
                stdout,
                "proposal version: {}",
                report.outcome.erase.proposal_version
            )?;
            writeln!(
                stdout,
                "retention mode: {}",
                report.outcome.erase.retention_mode
            )?;
            writeln!(stdout, "erased: {rendered}")
        })
    };
    write_result(result, stderr)
}

fn data_operation_name(operation: DataOperationArg) -> &'static str {
    match operation {
        DataOperationArg::Create => "create",
        DataOperationArg::Patch => "patch",
    }
}

fn write_migration_explain_human(
    report: &MigrationExplainSuccessReport,
    stdout: &mut dyn Write,
) -> io::Result<()> {
    let plan = &report.plan;
    let counts = plan.change_counts();
    writeln!(stdout, "migration explain succeeded")?;
    writeln!(stdout, "assurance: runtime_bound")?;
    writeln!(stdout, "package revision: {}", report.package_revision)?;
    writeln!(stdout, "plan kind: {}", plan_kind_name(plan.plan_kind()))?;
    writeln!(stdout, "has prior revision: {}", plan.has_prior_revision())?;
    writeln!(stdout, "has prior baseline: {}", plan.has_prior_baseline())?;
    writeln!(stdout, "change count: {}", plan.change_count())?;
    writeln!(
        stdout,
        "compatible additive changes: {}",
        counts.compatible_additive()
    )?;
    writeln!(
        stdout,
        "data backfill required changes: {}",
        counts.data_backfill_required()
    )?;
    writeln!(
        stdout,
        "access or disclosure changes: {}",
        counts.access_or_disclosure_change()
    )?;
    writeln!(
        stdout,
        "destructive or irreversible changes: {}",
        counts.destructive_or_irreversible()
    )?;
    writeln!(stdout, "unsupported changes: {}", counts.unsupported())?;
    writeln!(
        stdout,
        "generated statement count: {}",
        plan.generated_statement_count()
    )?;
    writeln!(
        stdout,
        "reviewed migration count: {}",
        plan.reviewed_migrations().len()
    )?;
    for (index, migration) in plan.reviewed_migrations().iter().enumerate() {
        let number = index + 1;
        writeln!(
            stdout,
            "reviewed migration {number} change class: {}",
            change_class_name(migration.change_class())
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} recovery: {}",
            recovery_name(migration.recovery())
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} lock timeout ms: {}",
            migration.lock_timeout_ms()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} statement timeout ms: {}",
            migration.statement_timeout_ms()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} transactional step count: {}",
            migration.transactional_step_count()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} chunked step count: {}",
            migration.chunked_step_count()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} pre-assertion count: {}",
            migration.pre_assertion_count()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} post-assertion count: {}",
            migration.post_assertion_count()
        )?;
        writeln!(
            stdout,
            "reviewed migration {number} backup required: {}",
            migration.backup_required()
        )?;
        if let Some(bounds) = migration.chunked_step_bounds() {
            writeln!(
                stdout,
                "reviewed migration {number} minimum chunk size: {}",
                bounds.minimum_chunk_size()
            )?;
            writeln!(
                stdout,
                "reviewed migration {number} maximum chunk size: {}",
                bounds.maximum_chunk_size()
            )?;
            writeln!(
                stdout,
                "reviewed migration {number} maximum total rows: {}",
                bounds.maximum_total_rows()
            )?;
        }
    }
    Ok(())
}

fn plan_kind_name(kind: MigrationInspectionPlanKind) -> &'static str {
    match kind {
        MigrationInspectionPlanKind::Initial => "initial",
        MigrationInspectionPlanKind::CompatibleAdditive => "compatible_additive",
        MigrationInspectionPlanKind::Reviewed => "reviewed",
    }
}

fn change_class_name(class: CompiledRegistryChangeClass) -> &'static str {
    match class {
        CompiledRegistryChangeClass::CompatibleAdditive => "compatible_additive",
        CompiledRegistryChangeClass::DataBackfillRequired => "data_backfill_required",
        CompiledRegistryChangeClass::AccessOrDisclosureChange => "access_or_disclosure_change",
        CompiledRegistryChangeClass::DestructiveOrIrreversible => "destructive_or_irreversible",
        CompiledRegistryChangeClass::Unsupported => "unsupported",
    }
}

fn recovery_name(recovery: ReviewedMigrationRecovery) -> &'static str {
    match recovery {
        ReviewedMigrationRecovery::ExactTargetResume => "exact_target_resume",
    }
}

fn write_diff_success(
    report: &DiffSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        writeln!(stdout, "diff succeeded").and_then(|()| {
            writeln!(stdout, "profile: authoring")?;
            writeln!(
                stdout,
                "baseline assurance: {}",
                match report.baseline_assurance {
                    BaselineAssurance::RuntimeBound => "runtime_bound",
                    BaselineAssurance::IntegrityOnly => "integrity_only",
                }
            )?;
            writeln!(
                stdout,
                "baseline package revision: {}",
                report.diff.baseline_package_revision
            )?;
            writeln!(
                stdout,
                "baseline registry revision: {}",
                report.diff.baseline_registry_revision
            )?;
            writeln!(
                stdout,
                "candidate registry revision: {}",
                report.diff.candidate_registry_revision
            )?;
            writeln!(stdout, "changes: {}", report.diff.changes.len())?;
            for change in &report.diff.changes {
                let rendered = serde_json::to_string(change).map_err(io::Error::other)?;
                writeln!(stdout, "change: {rendered}")?;
            }
            for finding in &report.findings {
                writeln!(
                    stdout,
                    "finding {} at {}: {}",
                    finding.code, finding.path, finding.message
                )?;
            }
            Ok(())
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "registry-serverctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_failure(
    report: &FailureReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        report.diagnostics.iter().try_for_each(|diagnostic| {
            writeln!(
                stderr,
                "error {} at {}: {}",
                diagnostic.code, diagnostic.path, diagnostic.message
            )
        })
    };
    if result.is_err() {
        let _ = writeln!(stderr, "registry-serverctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }
    ExitCode::from(DOMAIN_REFUSAL_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    use registry_server::compile_project;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".registry-serverctl-unit-test-{}-{}",
                std::process::id(),
                STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("test directory is created");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.path.exists() {
                fs::remove_dir_all(&self.path).expect("test directory is removed");
            }
        }
    }

    #[test]
    fn rhai_planner_capture_enforces_normalized_relative_paths_and_source_bound() {
        let directory = TestDirectory::create();
        fs::create_dir_all(directory.path.join("planners")).unwrap();
        fs::write(
            directory.path.join("planners/request.rhai"),
            b"fn plan(ctx) { #{ disposition: \"apply\", effects: [] } }\n",
        )
        .unwrap();
        let captured = load_planner_asset_files(
            &directory.path,
            "registry.yaml",
            BTreeSet::from(["planners/request.rhai".to_owned()]),
        )
        .expect("safe project-relative planner is captured");
        assert_eq!(captured[0].path, "planners/request.rhai");

        for path in [
            "../request.rhai",
            "/request.rhai",
            "planners//request.rhai",
            "planners/request.sql",
            "planners\\request.rhai",
        ] {
            assert_eq!(
                validate_rhai_planner_asset_path("registry.yaml", path)
                    .unwrap_err()
                    .code,
                "source.planner_asset.path_unsafe"
            );
        }

        fs::write(
            directory.path.join("planners/oversized.rhai"),
            vec![b'x'; MAX_RHAI_PLANNER_SOURCE_BYTES as usize + 1],
        )
        .unwrap();
        let oversized = load_planner_asset_files(
            &directory.path,
            "registry.yaml",
            BTreeSet::from(["planners/oversized.rhai".to_owned()]),
        )
        .unwrap_err();
        assert_eq!(oversized.code, "source.file.bounds");
    }

    #[test]
    fn project_planner_test_parser_requires_entity_and_request_file() {
        let parsed = Cli::try_parse_from([
            "registry-serverctl",
            "project",
            "planner-test",
            "project",
            "--entity",
            "request",
            "--request",
            "request.json",
        ])
        .expect("planner test parses");
        let Command::Project(project) = parsed.command else {
            panic!("project command parsed");
        };
        let ProjectCommand::PlannerTest(args) = project.command else {
            panic!("planner-test command parsed");
        };
        assert_eq!(args.project, PathBuf::from("project"));
        assert_eq!(args.entity, "request");
        assert_eq!(args.request, PathBuf::from("request.json"));
        assert!(Cli::try_parse_from([
            "registry-serverctl",
            "project",
            "planner-test",
            "project",
            "--entity",
            "request",
        ])
        .is_err());
    }

    #[test]
    fn change_request_explain_reports_source_free_rhai_contract_and_authority() {
        let compiled = match compile(&planner_acceptance_root(), ProfileArg::Authoring, "explain") {
            Ok(compiled) => compiled,
            Err(failure) => panic!(
                "Rhai fixture did not compile for explanation: {}",
                failure.diagnostics[0].code
            ),
        };
        let explanation = explain_change_requests(&compiled).expect("explanation renders");
        let request = explanation["requests"]
            .as_array()
            .and_then(|requests| {
                requests.iter().find(|request| {
                    request["requestEntity"].as_str() == Some("person-name-change-request")
                })
            })
            .expect("Rhai request is explained");
        assert_eq!(request["planner"]["kind"], "rhai");
        assert_eq!(
            request["planner"]["abi"],
            registry_server::contract::CHANGE_REQUEST_PLAN_ABI_V1
        );
        assert_eq!(
            request["planner"]["rhaiVersion"],
            registry_server::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
        );
        assert!(request["planner"]["scriptSha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(
            request["planner"]["declaringOrigin"],
            json!({"kind": "project"})
        );
        assert_eq!(request["planner"]["limits"]["maximumOperations"], 100_000);
        assert_eq!(request["planner"]["limits"]["maximumModules"], 0);
        assert_eq!(
            request["planner"]["possibleWrites"][0]["operation"],
            "patch"
        );
        assert_eq!(request["reviewMode"], "none");
        assert_eq!(request["application"]["mode"], "planner");
        assert_eq!(
            request["application"]["allowedDispositions"],
            json!(["apply", "queue"])
        );
        assert!(explanation["controlledWrites"]
            .as_array()
            .and_then(|writes| writes.iter().find(|write| write["entity"] == "person"))
            .and_then(|write| write["eligibleRequestTypes"].as_array())
            .is_some_and(|requests| requests
                .iter()
                .any(|request| { request.as_str() == Some("person-name-change-request") })));

        let rendered = serde_json::to_string(&explanation).expect("explanation serializes");
        for forbidden in [
            "person-name-change.rhai",
            "scripts/",
            "fn plan",
            "let display_name",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "explanation leaked {forbidden}"
            );
        }
    }

    #[test]
    fn project_planner_test_output_is_canonical_and_value_free() {
        let directory = TestDirectory::create();
        let request_path = directory.path.join("request.json");
        let record_id = "550e8400-e29b-41d4-a716-446655440000";
        let given_name = "given-name-secret-canary";
        let family_name = "family-name-secret-canary";
        fs::write(
            &request_path,
            serde_json::to_vec(&json!({
                "person": record_id,
                "given-name": given_name,
                "family-name": family_name,
                "handling": "assisted",
            }))
            .unwrap(),
        )
        .unwrap();
        let project = planner_acceptance_root();
        let arguments = vec![
            OsString::from("registry-serverctl"),
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("project"),
            OsString::from("planner-test"),
            project.into_os_string(),
            OsString::from("--entity"),
            OsString::from("person-name-change-request"),
            OsString::from("--request"),
            request_path.clone().into_os_string(),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_from(arguments, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let rendered = String::from_utf8(stdout).expect("planner summary is UTF-8");
        let value: Value = serde_json::from_str(rendered.trim_end()).expect("summary is JSON");
        let mut canonical = canonicalize_json(&value).expect("summary canonicalizes");
        canonical.push(b'\n');
        assert_eq!(rendered.as_bytes(), canonical);
        assert_eq!(value["planner"]["kind"], "rhai");
        assert_eq!(value["planner"]["abi"], "registry.change-request-plan/v1");
        assert!(value["planner"]["scriptSha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:")));
        assert_eq!(value["disposition"], "queue");
        assert_eq!(value["queueReason"]["code"], "assisted-review");
        assert_eq!(value["effects"][0]["id"], "effect-1");
        assert_eq!(value["effects"][0]["targetKind"], "existing");
        assert_eq!(value["effects"][0]["operation"], "patch");
        assert_eq!(value["effects"][0]["fields"], json!(["display-name"]));
        assert_eq!(value["effects"][0]["dependsOn"], json!([]));
        assert_eq!(value["counts"]["effects"], 1);
        assert_eq!(value["counts"]["fieldMutations"], 1);
        for redacted in [
            record_id,
            given_name,
            family_name,
            "person-name-change.rhai",
            "scripts/",
            "let display_name",
        ] {
            assert!(!rendered.contains(redacted), "leaked {redacted}");
        }

        let dynamic_project = directory.path.join("dynamic-project");
        fs::create_dir_all(dynamic_project.join("scripts")).unwrap();
        fs::copy(
            planner_acceptance_root().join("registry.yaml"),
            dynamic_project.join("registry.yaml"),
        )
        .unwrap();
        fs::write(
            dynamic_project.join("scripts/person-name-change.rhai"),
            br#"fn plan(ctx) {
                #{
                    effects: [#{
                        id: ctx.request["given-name"],
                        target: #{fromField: "person"},
                        operation: "patch",
                        set: #{"display-name": ctx.request["family-name"]}
                    }],
                    disposition: "apply"
                }
            }
            "#,
        )
        .unwrap();
        let dynamic = match planner_test(&ProjectPlannerTestArgs {
            project: dynamic_project,
            entity: "person-name-change-request".to_owned(),
            request: request_path,
        }) {
            Ok(report) => report,
            Err(failure) => panic!(
                "dynamic planner was refused with {}",
                failure.diagnostics[0].code
            ),
        };
        assert_eq!(dynamic.effects[0].id, "effect-1");
        let dynamic = serde_json::to_string(&dynamic).expect("dynamic summary renders");
        for redacted in [record_id, given_name, family_name] {
            assert!(!dynamic.contains(redacted), "leaked {redacted}");
        }
    }

    #[test]
    fn project_planner_test_refusals_are_stable_and_value_free() {
        let directory = TestDirectory::create();
        let request_path = directory.path.join("request.json");
        let project = planner_acceptance_root();

        fs::write(&request_path, b"{").unwrap();
        assert_planner_test_failure(
            &project,
            "person-name-change-request",
            &request_path,
            "planner_test.request.invalid",
        );

        let canary = "unbounded-secret-canary".repeat(900);
        fs::write(
            &request_path,
            serde_json::to_vec(&json!({"given-name": canary})).unwrap(),
        )
        .unwrap();
        assert_planner_test_failure(
            &project,
            "person-name-change-request",
            &request_path,
            "planner_test.request.bounds",
        );

        fs::write(&request_path, br#"{"undeclared-secret":"canary"}"#).unwrap();
        assert_planner_test_failure(
            &project,
            "person-name-change-request",
            &request_path,
            "planner_test.request.fields",
        );

        fs::write(&request_path, b"{}").unwrap();
        assert_planner_test_failure(
            &project,
            "person",
            &request_path,
            "planner_test.entity.not_request",
        );
        assert_planner_test_failure(
            &project,
            "person-name-change-request",
            &request_path,
            "change_request.planner.execution",
        );

        let declarative = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/registry-server/acceptance/asset-site-placement-change-requests")
            .canonicalize()
            .expect("declarative fixture canonicalizes");
        assert_planner_test_failure(
            &declarative,
            "placement-correction-request",
            &request_path,
            "planner_test.planner.declarative",
        );
    }

    fn assert_planner_test_failure(
        project: &Path,
        entity: &str,
        request: &Path,
        expected_code: &str,
    ) {
        let failure = planner_test(&ProjectPlannerTestArgs {
            project: project.to_owned(),
            entity: entity.to_owned(),
            request: request.to_owned(),
        })
        .expect_err("planner test is refused");
        assert_eq!(failure.diagnostics.len(), 1);
        assert_eq!(failure.diagnostics[0].code, expected_code);
        let rendered = serde_json::to_string(&failure).expect("failure renders");
        for redacted in [
            "unbounded-secret-canary",
            "undeclared-secret",
            "person-name-change.rhai",
            "scripts/",
        ] {
            assert!(!rendered.contains(redacted), "leaked {redacted}");
        }
    }

    fn planner_acceptance_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/registry-server/acceptance/person-name-change-rhai")
            .canonicalize()
            .expect("planner fixture canonicalizes")
    }

    fn migration_transaction_fixture(
        directory: &TestDirectory,
    ) -> BTreeMap<String, (Vec<u8>, Vec<u8>)> {
        let module_directory = directory.path.join("modules/core");
        fs::create_dir_all(&module_directory).expect("module directory creates");
        fs::write(
            directory.path.join("registry.yaml"),
            b"registry: original\n",
        )
        .expect("registry source writes");
        fs::write(module_directory.join("module.yaml"), b"module: original\n")
            .expect("module source writes");
        BTreeMap::from([
            (
                "registry.yaml".to_owned(),
                (
                    b"registry: original\n".to_vec(),
                    b"registry: migrated\n".to_vec(),
                ),
            ),
            (
                "modules/core/module.yaml".to_owned(),
                (
                    b"module: original\n".to_vec(),
                    b"module: migrated\n".to_vec(),
                ),
            ),
        ])
    }

    fn assert_no_migration_transaction_directories(directory: &TestDirectory) {
        for parent in [
            directory.path.as_path(),
            &directory.path.join("modules/core"),
        ] {
            let names = fs::read_dir(parent)
                .expect("directory is readable")
                .map(|entry| entry.expect("entry is readable").file_name())
                .collect::<Vec<_>>();
            assert!(
                names.iter().all(|name| !name
                    .to_string_lossy()
                    .starts_with(".registry-serverctl-migrate-")),
                "staging directory remains in {parent:?}: {names:?}"
            );
        }
    }

    #[test]
    fn project_migration_staging_failure_changes_no_target() {
        let directory = TestDirectory::create();
        let files = migration_transaction_fixture(&directory);

        let failure = write_migration_files_with_fault(
            &directory.path,
            &files,
            MigrationWriteFault::Stage(1),
        )
        .expect_err("injected staging failure refuses the transaction");

        assert_eq!(failure.code, "project.migrate.write_failed");
        assert_eq!(
            fs::read(directory.path.join("registry.yaml")).unwrap(),
            b"registry: original\n"
        );
        assert_eq!(
            fs::read(directory.path.join("modules/core/module.yaml")).unwrap(),
            b"module: original\n"
        );
        assert_no_migration_transaction_directories(&directory);
    }

    #[test]
    fn project_migration_concurrent_change_advances_no_other_target() {
        let directory = TestDirectory::create();
        let files = migration_transaction_fixture(&directory);

        let failure = write_migration_files_with_fault(
            &directory.path,
            &files,
            MigrationWriteFault::ConcurrentChange(1),
        )
        .expect_err("concurrent source edit refuses the transaction");

        assert_eq!(failure.code, "project.migrate.concurrent_change");
        // BTree ordering puts the module at index zero and registry at one.
        assert_eq!(
            fs::read(directory.path.join("modules/core/module.yaml")).unwrap(),
            b"module: original\n"
        );
        assert_eq!(
            fs::read(directory.path.join("registry.yaml")).unwrap(),
            b"concurrent author edit\n"
        );
        assert_no_migration_transaction_directories(&directory);
    }

    #[test]
    fn project_migration_late_commit_failure_restores_every_target() {
        let directory = TestDirectory::create();
        let files = migration_transaction_fixture(&directory);

        let failure = write_migration_files_with_fault(
            &directory.path,
            &files,
            MigrationWriteFault::Commit(1),
        )
        .expect_err("injected late commit failure rolls back");

        assert_eq!(failure.code, "project.migrate.write_failed");
        assert_eq!(
            fs::read(directory.path.join("registry.yaml")).unwrap(),
            b"registry: original\n"
        );
        assert_eq!(
            fs::read(directory.path.join("modules/core/module.yaml")).unwrap(),
            b"module: original\n"
        );
        assert_no_migration_transaction_directories(&directory);
    }

    #[test]
    fn public_command_surface_is_explicit() {
        let command = command();
        let names: Vec<_> = command
            .get_subcommands()
            .filter(|command| !command.is_hide_set() && command.get_name() != "help")
            .map(clap::Command::get_name)
            .collect();
        assert_eq!(
            names,
            [
                "init",
                "check",
                "project",
                "generate",
                "explain",
                "diff",
                "package",
                "test",
                "apply",
                "doctor",
                "verify",
                "migration",
                "history",
                "data",
                "webhook",
                "request-retention"
            ]
        );
    }

    #[test]
    fn global_format_is_accepted_before_or_after_the_subcommand() {
        for arguments in [
            vec!["registry-serverctl", "--format", "json", "check", "project"],
            vec!["registry-serverctl", "check", "project", "--format", "json"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }

    #[test]
    fn history_rebaseline_takes_only_the_runtime_config_and_request_file() {
        let parsed = Cli::try_parse_from([
            "registry-serverctl",
            "history",
            "rebaseline",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--request-file",
            "/tmp/request.json",
        ])
        .expect("history rebaseline parses");
        let Command::History(args) = parsed.command else {
            panic!("history command parsed");
        };
        let HistoryCommand::Rebaseline(args) = args.command else {
            panic!("history rebaseline command parsed");
        };
        assert_eq!(args.runtime_config, PathBuf::from("/tmp/runtime.yaml"));
        assert_eq!(args.request_file, PathBuf::from("/tmp/request.json"));
        assert!(Cli::try_parse_from([
            "registry-serverctl",
            "history",
            "rebaseline",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--record-id",
            "018feaa0-68f9-4a45-b9e3-58436df07af7",
        ])
        .is_err());
    }

    #[test]
    fn history_erase_requires_request_file_not_inline_target_values() {
        let parsed = Cli::try_parse_from([
            "registry-serverctl",
            "history",
            "erase",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--request-file",
            "/tmp/request.json",
        ])
        .expect("history erase parses");
        let Command::History(args) = parsed.command else {
            panic!("history command parsed");
        };
        let HistoryCommand::Erase(args) = args.command else {
            panic!("history erase command parsed");
        };
        assert_eq!(args.runtime_config, PathBuf::from("/tmp/runtime.yaml"));
        assert_eq!(args.request_file, PathBuf::from("/tmp/request.json"));
        assert!(Cli::try_parse_from([
            "registry-serverctl",
            "history",
            "erase",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--record-id",
            "018feaa0-68f9-4a45-b9e3-58436df07af7",
        ])
        .is_err());
    }

    #[test]
    fn history_erase_success_report_is_value_free() {
        let report = HistoryEraseSuccessReport {
            ok: true,
            command: "history erase",
            outcome: HistoryErasureLifecycleOutcome {
                package_revision: "pkg-1".to_owned(),
                coverage_ready: false,
                unavailable_after_position: None,
                affected_commit_count: 1,
                erased_revision_count: 2,
                erased_commit_member_count: 1,
                scrubbed_change_context_count: 1,
                scrubbed_outbox_payload_count: 1,
                scrubbed_cached_response_count: 1,
                removed_descriptor_count: 0,
            },
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        assert_eq!(
            write_history_erase_success(&report, OutputFormat::Json, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        let rendered = String::from_utf8(stdout).expect("json is utf8");
        assert!(rendered.contains("\"command\": \"history erase\""));
        assert!(rendered.contains("\"scrubbedCachedResponseCount\": 1"));
        assert!(!rendered.contains("018feaa0-68f9-4a45-b9e3-58436df07af7"));
        assert!(!rendered.contains("operator"));
        assert!(!rendered.contains("reason"));
    }

    #[test]
    fn doctor_success_output_is_stable_in_human_and_machine_formats() {
        for (format, expected) in [
            (OutputFormat::Human, "doctor succeeded\n"),
            (
                OutputFormat::Json,
                "{\n  \"ok\": true,\n  \"command\": \"doctor\"\n}\n",
            ),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            assert_eq!(
                write_doctor_success(format, &mut stdout, &mut stderr),
                ExitCode::SUCCESS
            );
            assert_eq!(
                String::from_utf8(stdout).expect("output is UTF-8"),
                expected
            );
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn legacy_json_profile_and_full_generate_forms_are_not_accepted() {
        for arguments in [
            vec!["registry-serverctl", "--json", "check", "project"],
            vec![
                "registry-serverctl",
                "check",
                "project",
                "--profile",
                "production",
            ],
            vec![
                "registry-serverctl",
                "generate",
                "project",
                "--output",
                "out",
            ],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn publication_refuses_a_destination_created_after_staging() {
        let project = parse_project_yaml(
            br#"
apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: example-registry
  version: 0.1.0
  defaultLanguage: en
  canonicalBaseIri: https://example-registry.example.test
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: mutable
    fields:
      - id: code
        type: string
        required: true
        maxLength: 64
        classification: internal
accessProfiles:
  - id: operator
    principalClaim: registry_principal
    requiredPurposes: [operations]
    grants:
      - entity: record
        operations: [create, get, list, patch]
        readableFields: [code]
        writableFields: [code]
"#,
        )
        .expect("domain-neutral test project parses");
        let compiled = compile_project(&project, &[], CompileProfile::Authoring)
            .expect("domain-neutral test project compiles");
        let directory = TestDirectory::create();
        let destination = directory.path.join("output");

        let failure = write_artifacts_with_before_publish(
            &destination,
            compiled.artifacts(),
            |destination| {
                fs::create_dir(destination).map_err(|_| {
                    diagnostic(
                        "test.setup.failed",
                        "test",
                        "the test destination could not be created",
                    )
                })?;
                fs::write(destination.join("preserved.txt"), b"preserved").map_err(|_| {
                    diagnostic(
                        "test.setup.failed",
                        "test",
                        "the test destination could not be written",
                    )
                })
            },
        )
        .expect_err("publication must not replace a destination created after staging");

        assert_eq!(failure.code, "output.publish.failed");
        assert_eq!(
            fs::read(destination.join("preserved.txt")).expect("existing destination is intact"),
            b"preserved"
        );
        assert!(fs::read_dir(&directory.path)
            .expect("test directory is readable")
            .all(|entry| {
                !entry
                    .expect("test directory entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".registry-serverctl-stage-")
            }));
    }

    #[test]
    fn rebaseline_history_diagnostics_point_at_the_retained_history() {
        use registry_server::history_rebaseline::{
            HistoryRebaselineError, MAX_REBASELINE_LIVE_ROWS,
        };

        for (error, code) in [
            (
                HistoryRebaselineError::UnindexedRevisions,
                "history.rebaseline.revisions.unindexed",
            ),
            (
                HistoryRebaselineError::LiveHistoryMismatch,
                "history.rebaseline.live_rows.unverified",
            ),
            (
                HistoryRebaselineError::LiveRowBudgetExceeded,
                "history.rebaseline.live_rows.budget_exceeded",
            ),
        ] {
            let report = history_rebaseline_lifecycle_failure(
                HistoryRebaselineLifecycleError::Rebaseline(error),
            );
            let diagnostic = &report.diagnostics[0];
            assert_eq!(diagnostic.code, code);
            assert_eq!(
                diagnostic.suggested_action,
                SuggestedAction::ReviewRetainedHistory,
                "the operator resolves {code} by reading the retained history, \
                 not by re-checking the migration authority"
            );
        }

        let budget =
            history_rebaseline_lifecycle_failure(HistoryRebaselineLifecycleError::Rebaseline(
                HistoryRebaselineError::LiveRowBudgetExceeded,
            ));
        assert_eq!(
            budget.diagnostics[0].message,
            format!(
                "history rebaseline verifies at most {MAX_REBASELINE_LIVE_ROWS} live rows in one \
                 transaction and this registry holds more, so retrying cannot restore snapshot \
                 coverage"
            ),
            "the budget diagnostic states the limit it enforces and what retrying cannot do"
        );

        let mismatch =
            history_rebaseline_lifecycle_failure(HistoryRebaselineLifecycleError::Rebaseline(
                HistoryRebaselineError::LiveHistoryMismatch,
            ));
        assert!(
            mismatch.diagnostics[0].message.contains("is not named"),
            "the mismatch diagnostic says the refusal identifies no record"
        );
    }

    #[test]
    fn initialized_runtime_example_parses_as_a_runtime_configuration() {
        // No command reads runtime.example.yaml, so this is what holds the
        // example to the grammar the runtime accepts.
        let raw = std::str::from_utf8(INIT_RUNTIME_EXAMPLE).expect("the example is UTF-8");
        registry_server::runtime_config::parse_runtime_config_with_env(raw, |_| None)
            .expect("the initialized runtime example parses");
    }
}
