// SPDX-License-Identifier: Apache-2.0
//! Deterministic Registry Server project checking and artifact generation.
//!
//! This crate owns filesystem orchestration and report rendering only. Model
//! parsing, validation, compilation, and artifact generation remain in
//! `registry-server`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_server::migration_plan::ReviewedMigrationRecovery;
use registry_server::package::{
    inspect_package_integrity, CompiledRegistryChangeClass, MigrationInspectionPlanKind,
    MigrationInspectionSummary, PackageBuildRequest, PackageError, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, PreparedPackage, SignaturePolicy,
    FIXTURE_JOURNEYS_PATH, MAX_PACKAGE_SOURCE_FILE_BYTES,
};
use registry_server::runtime_config::RuntimeConfigError;
use registry_server::tooling::{classify_registry_diff, CompiledRegistryDiff, DiffClassification};
use registry_server::{
    compile_project, parse_module_yaml, parse_project_yaml, CompileFailure, CompileProfile,
    CompiledRegistry, Diagnostic, DiagnosticSeverity, GeneratedArtifact, GeneratedArtifacts,
    RegistryModule, RegistryProject,
};
use serde::Serialize;
use serde_json::{json, Value};

mod apply_lifecycle;
mod data_lifecycle;
mod doctor;
mod package_inspection;
mod package_lifecycle;
mod test_lifecycle;

use apply_lifecycle::{ApplyLifecycleError, ApplyLifecycleRequest};
use data_lifecycle::{
    DataExportRequest, DataImportRequest, DataLifecycleError, DataValidateRequest,
};
use package_inspection::{inspect_runtime_package, RuntimePackageInspectionError};
use package_lifecycle::{PackageLifecycleError, PackageLifecycleState};
use registry_server::data::DataError;
use test_lifecycle::{TestLifecycleError, TestLifecycleRequest};

const DOMAIN_REFUSAL_EXIT: u8 = 1;
const USAGE_EXIT: u8 = 2;
const OPERATIONAL_FAILURE_EXIT: u8 = 3;
// Keep ctl-authored project and module source capture aligned with the
// schema-test package rederivation ceiling so source-size refusals occur
// before runtime secret resolution or database rehearsal. Broader package-file
// limits still apply to fixture journeys and generated package artifacts.
const AUTHORED_SOURCE_REDERIVATION_MAX_BYTES: u64 = 1024 * 1024;
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
    /// Create a minimal domain-neutral authoring project in a new directory.
    Init(InitArgs),
    /// Validate a Registry Server authoring project without opening a database.
    Check(CheckArgs),
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
    /// Validate, import, or export data through authenticated Registry HTTP APIs.
    Data(DataArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// New directory that will receive the minimal project closure.
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
    #[arg(long, value_name = "SHA256")]
    schema_fingerprint: String,

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
struct DataArgs {
    #[command(subcommand)]
    command: DataCommand,
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
}

#[derive(Debug, Args)]
struct MigrationExplainArgs {
    /// Absolute Registry Server runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
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
    VerifyStartupDependencies,
    CorrectDataBinding,
    CorrectDataInput,
    VerifyDataCheckpoint,
    VerifyDataTransport,
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

#[derive(Debug)]
struct CapturedProjectSource {
    project: RegistryProject,
    project_bytes: Vec<u8>,
    modules: Vec<CapturedModuleSource>,
}

#[derive(Debug)]
struct CapturedModuleSource {
    id: String,
    module: RegistryModule,
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
    modules: Vec<PackageModuleSource>,
    fixture_journeys: PackageSourceFile,
    migration_plan: PackageMigrationPlanInput,
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
        if config.identity().environment() != self.environment
            || config.identity().instance_id() != self.instance_id
            || config.identity().database_id() != self.database_id
            || config.package().compiler_source_revision() != self.compiler_source_revision
        {
            return Err(TestLifecycleError::Candidate);
        }
        Ok(())
    }

    fn prevalidate(&self) -> Result<(), PackageError> {
        const PLACEHOLDER_SCHEMA_FINGERPRINT: &str =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        self.clone()
            .prepare(PLACEHOLDER_SCHEMA_FINGERPRINT.to_owned())
            .map(|_| ())
    }

    fn prepare(self, schema_fingerprint: String) -> Result<PreparedPackage, PackageError> {
        registry_server::package::prepare_package(PackageBuildRequest {
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
        })
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
            let report = FailureReport {
                ok: false,
                command: "usage",
                diagnostics: vec![tool_diagnostic(
                    diagnostic(
                        "usage.invalid",
                        "arguments",
                        "the command arguments are invalid",
                    ),
                    DiagnosticArtifact::CommandArguments,
                    SuggestedAction::CorrectCommandUsage,
                )],
            };
            let _ = write_failure(
                &report,
                if machine_mode {
                    OutputFormat::Json
                } else {
                    OutputFormat::Human
                },
                stdout,
                stderr,
            );
            return ExitCode::from(USAGE_EXIT);
        }
    };

    let format = cli.format;
    let result = match cli.command {
        Command::Init(args) => init(&args.destination),
        Command::Check(args) => check(&args.project, profile(args.production)),
        Command::Generate(args) => generate(
            args.artifact,
            &args.project,
            profile(args.production),
            &args.output,
        ),
        Command::Explain(args) => explain(args.subject, &args.project, profile(args.production)),
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
    };

    match result {
        Ok(report) => write_success(&report, format, stdout, stderr),
        Err(failure) => write_failure(&failure, format, stdout, stderr),
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
    let prepared = prepare_candidate(&args.candidate, args.schema_fingerprint.clone(), "package")?;
    let receipt = package_lifecycle::validate_test_receipt(&args.test_receipt, &prepared)
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
    let modules = source
        .modules
        .into_iter()
        .map(|module| PackageModuleSource {
            path: format!("source/modules/{}/module.yaml", module.id),
            id: module.id,
            bytes: module.bytes,
        })
        .collect();
    let fixture_journey_bytes = read_bounded_regular_file(
        &args.project.join(FIXTURE_JOURNEYS_PATH),
        "source.fixture_journeys.missing",
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
    let (prior_revision, migration_plan) = match args.baseline_runtime_config.as_deref() {
        Some(runtime_config) => {
            let baseline = inspect_runtime_package(runtime_config)
                .map_err(|error| inspection_failure(command, "package.baseline", error))?;
            (
                Some(baseline.package_revision().to_owned()),
                PackageMigrationPlanInput::Successor {
                    prior_registry: Box::new(baseline.registry().clone()),
                },
            )
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
    Ok(CapturedPackageCandidate {
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
        modules,
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: fixture_journey_bytes,
        },
        migration_plan,
    })
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
        PackageLifecycleError::TestReceiptRefused | PackageLifecycleError::TestReceiptEvidence => {
            package_failure(
                "package.test_receipt.refused",
                "testReceipt",
                "the schema-test receipt was refused",
                DiagnosticArtifact::SchemaTestReceipt,
                SuggestedAction::SupplySchemaTestReceipt,
            )
        }
    }
}

fn test_lifecycle_failure(error: TestLifecycleError) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        TestLifecycleError::RuntimeConfigPath => (
            "test.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        TestLifecycleError::RuntimeConfig(RuntimeConfigError::UnsafeFile) => (
            "test.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path is unsafe",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        TestLifecycleError::RuntimeConfig(_) => (
            "test.runtime_config.refused",
            "runtimeConfig",
            "the runtime configuration was refused",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        TestLifecycleError::Candidate => (
            "test.candidate.refused",
            "candidate",
            "the schema-test package candidate was refused",
            DiagnosticArtifact::SchemaTestCandidate,
            SuggestedAction::CorrectSchemaTestCandidate,
        ),
        TestLifecycleError::Journeys => (
            "test.journeys.refused",
            "journeys",
            "the packaged schema-test journey suite was refused",
            DiagnosticArtifact::FixtureJourneys,
            SuggestedAction::CorrectFixtureJourneys,
        ),
        TestLifecycleError::Credentials => (
            "test.credentials.refused",
            "credentials",
            "the schema-test credential bindings were refused",
            DiagnosticArtifact::SchemaTestCredentials,
            SuggestedAction::SupplySchemaTestCredentials,
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
    let (code, path, message, artifact, action) = match error {
        ApplyLifecycleError::RuntimeConfigPath => (
            "apply.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::RuntimeConfig => (
            "apply.runtime_config.refused",
            "runtimeConfig",
            "the runtime configuration was refused",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
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

fn inspection_failure(
    command: &'static str,
    prefix: &'static str,
    error: RuntimePackageInspectionError,
) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        RuntimePackageInspectionError::RuntimeConfigPath => (
            format!("{prefix}.runtime_config.path_invalid"),
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        RuntimePackageInspectionError::RuntimeConfig(RuntimeConfigError::UnsafeFile) => (
            format!("{prefix}.runtime_config.path_invalid"),
            "runtimeConfig",
            "the runtime configuration path is unsafe",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        RuntimePackageInspectionError::RuntimeConfig(_) => (
            format!("{prefix}.runtime_config.refused"),
            "runtimeConfig",
            "the runtime configuration was refused",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
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
    match error {
        RuntimeConfigError::UnsafeFile => diff_failure(
            "diff.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path is unsafe",
        ),
        _ => diff_failure(
            "diff.runtime_config.refused",
            "runtimeConfig",
            "the runtime configuration was refused",
        ),
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
            .map(|(path, bytes)| artifact_report(path, "text/yaml", bytes))
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

fn explain(
    subject: ExplainSubject,
    project_path: &Path,
    profile: ProfileArg,
) -> Result<SuccessReport, FailureReport> {
    let compiled = compile(project_path, profile, "explain")?;
    let explanation = match subject {
        ExplainSubject::Model => explain_model(&compiled),
        ExplainSubject::Access => serde_json::to_value(compiled.access()),
        ExplainSubject::Routes => serde_json::to_value(compiled.routes()),
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
    compile_project(&source.project, &modules, profile.into()).map_err(|failure| FailureReport {
        ok: false,
        command,
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
    })
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
    let project_bytes = read_bounded_regular_file(
        &project_path.join("registry.yaml"),
        "source.project.missing",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    let project = parse_project_yaml(&project_bytes).map_err(first_diagnostic)?;
    let modules = load_module_files(project_path, &project)?
        .into_iter()
        .map(|(id, bytes)| {
            let module = parse_module_yaml(&bytes).map_err(first_diagnostic)?;
            Ok(CapturedModuleSource { id, module, bytes })
        })
        .collect::<Result<Vec<_>, Diagnostic>>()?;
    Ok(CapturedProjectSource {
        project,
        project_bytes,
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
            let bytes = read_bounded_regular_file(
                &path,
                "source.module.missing",
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )?;
            Ok((id, bytes))
        })
        .collect()
}

fn init_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "registry.yaml".to_owned(),
            br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: generic-registry
  version: 0.1.0
  defaultLanguage: en
manifestProjection:
  accessProfile: operator
  classificationCeiling: internal
  catalog:
    baseUrl: https://registry.example.test
    title: Generic Registry Catalog
    publisher:
      name: Registry Operator
  dataset:
    title: Generic Registry Dataset
    owner: Registry Operator
    status: active
modules:
  - id: core
    version: 0.1.0
entities:
  - id: record
    route: records
    mutationMode: mutable
    fields:
      - id: code
        type: string
        required: true
        maxLength: 64
        classification: internal
      - id: label
        type: string
        required: true
        maxLength: 200
        classification: internal
    constraints:
      - kind: unique
        fields: [code]
accessProfiles:
  - id: operator
    principalClaim: registry_principal
    purposes: [registry-operations]
    grants:
      - entity: record
        actions: [create, get, list, patch]
        readableFields: [code, label]
        writableFields: [code, label]
"#
            .to_vec(),
        ),
        (
            "modules/core/module.yaml".to_owned(),
            br#"id: core
version: 0.1.0
"#
            .to_vec(),
        ),
        (
            FIXTURE_JOURNEYS_PATH.to_owned(),
            br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: record-lifecycle
    steps:
      - id: create-record
        entity: record
        accessProfile: operator
        claims: &operator_claims
          principal: fixture-operator
          purpose: registry-operations
        request:
          operation: create
          data: {code: example, label: Example record}
        expect:
          outcome: success
          status: 201
          fields: {code: example, label: Example record}
        capture: example-record
      - id: get-record
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request: {operation: get, recordRef: example-record}
        expect:
          outcome: success
          status: 200
          fields: {code: example, label: Example record}
      - id: list-records
        entity: record
        accessProfile: operator
        claims: *operator_claims
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 1}
"#
            .to_vec(),
        ),
    ])
}

fn selected_artifacts(
    artifacts: &GeneratedArtifacts,
    selector: ArtifactSelector,
) -> Result<Vec<GeneratedArtifact>, Diagnostic> {
    let selected: Vec<_> = artifacts
        .entries()
        .values()
        .filter(|artifact| match selector {
            ArtifactSelector::Openapi => artifact.path == "generated/openapi.json",
            ArtifactSelector::Schemas => artifact.path.starts_with("generated/schemas/"),
            ArtifactSelector::Manifest => artifact.path.starts_with("generated/manifest/"),
            ArtifactSelector::Metadata => artifact.path == "generated/metadata/registry.json",
            ArtifactSelector::Sql => artifact.path == "generated/postgres/schema.sql",
        })
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err(diagnostic(
            "artifact.selection.empty",
            "artifacts",
            "the selected artifact is unavailable for this compiled project",
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

fn read_bounded_regular_file(
    path: &Path,
    missing_code: &str,
    bound: u64,
) -> Result<Vec<u8>, Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        diagnostic(
            missing_code,
            "project",
            "the required authoring source is not available",
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(diagnostic(
            "source.file.invalid",
            "project",
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    ensure_no_symlink_components(path, "source.file.invalid", "project")?;
    if metadata.len() > bound {
        return Err(diagnostic(
            "source.file.bounds",
            "project",
            "an authoring source exceeds its fixed size bound",
        ));
    }
    let file = File::open(path).map_err(|_| {
        diagnostic(
            "source.file.unreadable",
            "project",
            "an authoring source cannot be read",
        )
    })?;
    let opened = file.metadata().map_err(|_| {
        diagnostic(
            "source.file.unreadable",
            "project",
            "an authoring source cannot be read",
        )
    })?;
    let after = fs::symlink_metadata(path).map_err(|_| {
        diagnostic(
            "source.file.invalid",
            "project",
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
            "project",
            "authoring sources must be regular files and must not be symbolic links",
        ));
    }
    if opened.len() > bound {
        return Err(diagnostic(
            "source.file.bounds",
            "project",
            "an authoring source exceeds its fixed size bound",
        ));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| {
        diagnostic(
            "source.file.bounds",
            "project",
            "an authoring source exceeds its fixed size bound",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(bound.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| {
            diagnostic(
                "source.file.unreadable",
                "project",
                "an authoring source cannot be read",
            )
        })?;
    if bytes.len() as u64 > bound || bytes.len() as u64 != opened.len() {
        return Err(diagnostic(
            "source.file.bounds",
            "project",
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
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    validate_directory_for(
        parent,
        "output.parent.invalid",
        "output.parent",
        "the output parent directory is not available",
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
                "generate",
                "explain",
                "diff",
                "package",
                "test",
                "apply",
                "doctor",
                "verify",
                "migration",
                "data"
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
entities:
  - id: record
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
    purposes: [operations]
    grants:
      - entity: record
        actions: [create, get, list, patch]
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
}
