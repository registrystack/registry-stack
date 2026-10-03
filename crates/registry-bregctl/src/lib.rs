// SPDX-License-Identifier: Apache-2.0
//! Deterministic Base Registry Engine project checking and artifact generation.
//!
//! This crate owns filesystem orchestration and report rendering only. Model
//! parsing, validation, compilation, and artifact generation remain in
//! `breg`.

use anstream::AutoStream;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum};
use registry_breg::compiler::module_digest_with_assets;
use registry_breg::contract::{FieldTypeSource, ModuleAssetSource, ModuleLockSource};
use registry_breg::migration_plan::{ReviewedMigrationError, ReviewedMigrationRecovery};
use registry_breg::package::{
    inspect_package_integrity, CompiledRegistryChangeClass, MigrationInspectionPlanKind,
    MigrationInspectionSummary, PackageBuildRequest, PackageError, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, PreparedPackage, FIXTURE_JOURNEYS_PATH,
    MAX_PACKAGE_SOURCE_FILE_BYTES, MAX_RHAI_PLANNER_PATH_BYTES, MAX_RHAI_PLANNER_SOURCE_BYTES,
};
use registry_breg::postgres::{BaselineFingerprintDrift, MigrationRehearsalError};
use registry_breg::runtime_config::RuntimeConfigError;
use registry_breg::tooling::{classify_registry_diff, CompiledRegistryDiff, DiffClassification};
use registry_breg::{
    compile_project_with_assets, parse_module_yaml, parse_project_yaml, CompileFailure,
    CompileProfile, CompiledRegistry, Diagnostic, DiagnosticSeverity, GeneratedArtifact,
    GeneratedArtifacts, RegistryModule, RegistryProject,
};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_config::PackageDigestMismatch;
use registry_platform_hooks::HookHandlerSource;
use serde::Serialize;
use serde_json::{json, Value};

mod action_handler_test;
mod active_registry;
mod apply_lifecycle;
mod consent_module;
mod data_lifecycle;
mod dev;
mod doctor;
mod field_encryption;
mod field_encryption_lifecycle;
mod history_erasure_lifecycle;
mod history_rebaseline_lifecycle;
mod import_authority_lifecycle;
mod init_from_model;
mod instance_claim_lifecycle;
mod module_lock_patch;
mod package_inspection;
mod package_lifecycle;
mod reconcile_lifecycle;
mod report;
mod request_retention;
mod review_recovery;
mod reviewed_migrations;
mod safe_path;
mod starters;
mod test_lifecycle;
mod webhook_lifecycle;

use active_registry::ActiveRegistryError;
use apply_lifecycle::{
    ApplyLifecycleActivation, ApplyLifecycleError, ApplyLifecycleRequest, PlanLifecycleRequest,
};
use data_lifecycle::{
    DataExportRequest, DataImportRequest, DataLifecycleError, DataValidateRequest, ExportPairState,
};
use field_encryption_lifecycle::{
    FieldEncryptionEraseHistoryLifecycleError, FieldEncryptionEraseHistoryLifecycleOutcome,
    FieldEncryptionEraseHistoryLifecycleRequest, FieldEncryptionPreflightLifecycleError,
    FieldEncryptionPreflightLifecycleOutcome, FieldEncryptionPreflightLifecycleRequest,
};
use history_erasure_lifecycle::{
    HistoryErasureLifecycleError, HistoryErasureLifecycleOutcome, HistoryErasureLifecycleRequest,
};
use history_rebaseline_lifecycle::{
    HistoryRebaselineLifecycleError, HistoryRebaselineLifecycleOutcome,
    HistoryRebaselineLifecycleRequest,
};
use import_authority_lifecycle::ImportAuthorityCliError;
use instance_claim_lifecycle::InstanceClaimCliError;
use package_inspection::{
    inspect_baseline_package, inspect_baseline_rehearsal, inspect_runtime_package,
    inspect_runtime_predecessor_rehearsal_baseline, RuntimePackageInspectionError,
};
use package_lifecycle::PackageLifecycleError;
use reconcile_lifecycle::{
    ReconcileLifecycleError, ReconcileLifecycleOutcome, ReconcileLifecycleRequest,
};
use registry_breg::data::DataError;
use registry_breg::migration_reconcile::{ReconcileError, ReconcileOutcome};
use registry_breg_client::BRegIngestionBlockedReason;
use request_retention::{
    RequestRetentionCliError, RequestRetentionDryRunOutcome, RequestRetentionEraseOutcome,
    RequestRetentionListOutcome,
};
use review_recovery::{ReviewRecoveryCliError, ReviewRecoveryOperation, ReviewRecoveryOutcome};
use safe_path::{EntryStat, SafeDir, SafeEntry, SafePathError, MAX_REMOVE_TREE_DEPTH};
use test_lifecycle::{TestLifecycleError, TestLifecycleRequest};
use webhook_lifecycle::{
    WebhookDiscardOutcome, WebhookLifecycleError, WebhookListOutcome, WebhookReplayOutcome,
    WebhookSampleOutcome,
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
    name = "bregctl",
    version = registry_platform_buildinfo::DISPLAY_VERSION,
    about = "Base Registry Engine project checking and deterministic generation"
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
    /// Create an authoring project in a new directory: a domain-neutral example,
    /// one derived from an embedded reference model with `--from`, or a shipped
    /// starter with `--template`.
    Init(InitArgs),
    /// Validate a Base Registry Engine authoring project without opening a database.
    Check(CheckArgs),
    /// Maintain deterministic authoring project metadata.
    Project(ProjectArgs),
    /// Add generated modules to an authoring project.
    Module(ModuleArgs),
    /// Write selected compiler artifacts to a new directory.
    Generate(GenerateArgs),
    /// Start or stop this project's retained local development services.
    Dev(dev::DevArgs),
    /// List or explicitly run retained local teaching examples.
    Examples(dev::examples::ExamplesArgs),
    #[command(name = "__dev-supervisor", hide = true)]
    DevSupervisor(dev::SupervisorArgs),
    /// Explain compiled model, access, route, or event inventories.
    Explain(ExplainArgs),
    /// Compare an authoring candidate with a rederived closed package.
    Diff(DiffArgs),
    /// Build a deterministic production-profile package from a tested candidate.
    ///
    /// The package is the promotable unit `bregctl apply` activates: it is built from a project
    /// `bregctl test` passed, so it needs that run's --test-receipt. `caseworkctl package` is a
    /// different verb that writes a Casework project's checked policy to its own package.
    Package(PackageArgs),
    /// Execute the production schema-test journey suite for one package candidate.
    Test(TestArgs),
    /// Apply one built package using the configured migration authority.
    Apply(ApplyArgs),
    /// Report what `bregctl apply` would activate for one package, running its checks without changing the database.
    ///
    /// A plan uses the migration credential, because apply's checks read what only the migration
    /// role may read. It rolls back every check it runs, appends no audit entry, and holds the
    /// apply lock while it checks. Pending changes exit 0; a refusal exits 1 and names the fix.
    Plan(PlanArgs),
    /// Report the active package and the activation ledger the database records.
    ///
    /// Status reads as the migration role in one read-only transaction and takes no apply lock,
    /// so it answers while an apply runs.
    Status(StatusArgs),
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
    /// Recover a lost review or an automatic application blocked by executor authorization.
    ReviewRecovery(ReviewRecoveryArgs),
    /// Erase expired protected action Evidence using configured migration authority.
    EvidenceRetention(EvidenceRetentionArgs),
    /// Open, close, and list the authorities that bound `import` runs.
    ImportAuthority(ImportAuthorityArgs),
    /// Inspect and adopt the claim naming the database the Registry serves from.
    InstanceClaim(InstanceClaimArgs),
    /// Maintain field-encryption key material.
    FieldEncryption(FieldEncryptionArgs),
}

#[derive(Debug, Args)]
struct FieldEncryptionArgs {
    #[command(subcommand)]
    command: FieldEncryptionCommand,
}

#[derive(Debug, Subcommand)]
enum FieldEncryptionCommand {
    /// Write one fresh base64 data key for the local-file provider. The key
    /// never reaches standard output and an existing file is never overwritten.
    Keygen(FieldEncryptionKeygenArgs),

    /// Report what one reviewed backfill apply would do, before running it:
    /// value-free counts per covered field, the descriptor's explicit history
    /// choice, and the record names a unique blind index would refuse.
    Preflight(FieldEncryptionPreflightArgs),

    /// Erase the retained plaintext history of flips that declared
    /// erase-and-rebaseline, then restore snapshot coverage with one
    /// rebaseline. Runs only after the flip's package is active.
    EraseHistory(FieldEncryptionEraseHistoryArgs),
}

#[derive(Debug, Args)]
struct FieldEncryptionKeygenArgs {
    /// Absolute output path for the base64 data key (written 0600, parents 0700).
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct FieldEncryptionPreflightArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute directory of the verified successor package the operator
    /// plans to apply.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,
}

#[derive(Debug, Args)]
struct FieldEncryptionEraseHistoryArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute owner-only JSON erase-history request file.
    ///
    /// Read through the parent directory this path resolves to, so a `..`
    /// component is refused. The file must carry no group or other permission
    /// bits, because it authorizes destroying retained history.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    request_file: PathBuf,
}

#[derive(Debug, Args)]
struct EvidenceRetentionArgs {
    #[command(subcommand)]
    command: EvidenceRetentionCommand,
}

#[derive(Debug, Subcommand)]
enum EvidenceRetentionCommand {
    /// Delete expired assertion bytes and verification context; receipts remain replayable.
    EraseExpired(EvidenceRetentionEraseArgs),
}

#[derive(Debug, Args)]
struct EvidenceRetentionEraseArgs {
    /// Absolute runtime configuration path containing the migration connection binding.
    #[arg(long)]
    runtime_config: PathBuf,
    /// RFC 3339 expiry cutoff, no later than the current time.
    #[arg(long)]
    before: String,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// New directory that will receive the project closure.
    #[arg(value_name = "DESTINATION")]
    destination: PathBuf,
    /// Derive the project from an embedded reference model instead of writing
    /// the example. Without `--selection` or `--starter`, the command asks
    /// which concepts and properties to select at the terminal.
    #[arg(long, value_enum, value_name = "MODEL")]
    from: Option<init_from_model::ModelName>,
    /// A selection document naming the concepts and properties to derive;
    /// the written project echoes one under `model/selection.yaml`.
    #[arg(
        long,
        value_name = "FILE",
        requires = "from",
        conflicts_with = "starter"
    )]
    selection: Option<PathBuf>,
    /// A selection shipped with the model, by name.
    #[arg(long, value_name = "NAME", requires = "from")]
    starter: Option<String>,
    /// Write one of the shipped starter registry projects verbatim instead
    /// of the plain example or a project derived from `--from`.
    #[arg(
        long,
        value_name = "ID",
        value_parser = starters::value_parser(),
        conflicts_with_all = ["from", "selection", "starter"]
    )]
    template: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("checked")
        .required(true)
        .multiple(false)
        .args(["project", "package"])
))]
struct CheckArgs {
    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: Option<PathBuf>,

    /// Closed package to verify against its sums, reporting the registry revision it rederives.
    #[arg(long, value_name = "DIRECTORY", conflicts_with_all = ["production", "deny_findings"])]
    package: Option<PathBuf>,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,
    /// Exit unsuccessfully when any authoring finding needs review, including access warnings.
    #[arg(long)]
    deny_findings: bool,
}

#[derive(Debug, Args)]
struct ModuleArgs {
    #[command(subcommand)]
    command: ModuleCommand,
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    /// Write a generated module into the project and pin it in registry.yaml.
    Add(ModuleAddArgs),
}

#[derive(Debug, Args)]
struct ModuleAddArgs {
    #[command(subcommand)]
    module: ModuleAddCommand,
}

#[derive(Debug, Subcommand)]
enum ModuleAddCommand {
    /// Add consent for one subject entity: the privacy notice, its clauses,
    /// the principal link, the create-only consent decision, their self and
    /// steward actions, and five access profiles. Prints the requireConsent
    /// line that gates a permission on the decision.
    Consent(ModuleAddConsentArgs),
}

#[derive(Debug, Args)]
struct ModuleAddConsentArgs {
    /// Entity whose rows consent decisions are about.
    #[arg(long, value_name = "ENTITY")]
    subject: String,
    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,
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
    /// Test a Rhai request planner or action handler with bounded synthetic JSON.
    PlannerTest(ProjectPlannerTestArgs),
}

#[derive(Debug, Args)]
struct ProjectLockArgs {
    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Refuse when registry.yaml is not already locked instead of rewriting it.
    #[arg(long)]
    check: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("script_target").required(true).args(["entity", "action"])))]
struct ProjectPlannerTestArgs {
    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Compiled change-request entity whose Rhai planner will run; pair with --request.
    #[arg(
        long,
        value_name = "ENTITY",
        conflicts_with = "action",
        requires = "request"
    )]
    entity: Option<String>,

    /// Bounded strict JSON object containing synthetic request fields; requires --entity.
    #[arg(long, value_name = "JSON_FILE", requires = "entity", conflicts_with_all = ["action", "input", "expect"])]
    request: Option<PathBuf>,

    /// Compiled immediate action whose Rhai handler will run; pair with --input.
    #[arg(long, value_name = "ACTION", requires = "input")]
    action: Option<String>,

    /// Bounded strict JSON object using authored action input IDs, without an HTTP envelope; requires --action.
    #[arg(long, value_name = "JSON_FILE", requires = "action", conflicts_with_all = ["entity", "request"])]
    input: Option<PathBuf>,

    /// With --action and --input, assert exact effects or refusal and optional ordered evidenceCalls mocks without printing values.
    #[arg(long, value_name = "JSON_FILE", requires = "action", conflicts_with_all = ["entity", "request"])]
    expect: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct GenerateArgs {
    /// Artifact family to write.
    #[arg(value_name = "ARTIFACT", value_enum)]
    artifact: ArtifactSelector,

    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,

    /// New directory that will receive exactly the generated artifact inventory.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,

    /// Existing registry lookup access profile (evidence-source only).
    #[arg(long)]
    access_profile: Option<String>,
    /// Compiled entity to export (evidence-source only).
    #[arg(long)]
    entity: Option<String>,
    /// Exact lookup alternatives; repeat to expose several selectors.
    #[arg(long = "selector", value_delimiter = ',')]
    selectors: Vec<String>,
    /// Explicit readable fact fields, separated by commas.
    #[arg(long, value_delimiter = ',')]
    fields: Vec<String>,
    /// Stable source identity inside the Evidence authoring project.
    #[arg(long)]
    source_id: Option<String>,
    /// Logical connection that the Evidence operator configures separately.
    #[arg(long)]
    connection: Option<String>,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Compiled inventory to explain.
    #[arg(value_name = "SUBJECT", value_enum)]
    subject: ExplainSubject,

    /// Base Registry Engine project directory. Required for every subject
    /// except `lifecycle`, which reports engine behaviour no project changes.
    #[arg(value_name = "PROJECT")]
    project: Option<PathBuf>,

    /// Enforce production-only package closure requirements.
    #[arg(long)]
    production: bool,
    /// For access only: bounded JSON with synthetic claims. Performs no token verification or record access.
    #[arg(long, value_name = "JSON_FILE")]
    scenario: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct PackageCandidateArgs {
    /// Base Registry Engine project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Absolute directory of the chain tip package a successor follows. The
    /// same package directory is named in every environment.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    baseline_package: Option<PathBuf>,

    /// Directory containing reviewed migration descriptors and evidence in package layout. Used identically by test and package; requires a baseline package.
    #[arg(long, value_name = "DIRECTORY", requires = "baseline_package")]
    reviewed_migrations: Option<PathBuf>,
}

/// An `--expected-digest` value is a package digest in the form every command
/// prints one: `sha256:` and 64 lowercase hex digits.
fn parse_expected_digest(value: &str) -> Result<String, String> {
    if registry_platform_config::is_sha256_label(value) {
        Ok(value.to_owned())
    } else {
        Err("`--expected-digest` must be sha256: followed by 64 lowercase hex digits, the package digest as plan and package print it".to_owned())
    }
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

    /// New build directory that receives the schema-test receipt and the published package/.
    #[arg(long, value_name = "DIRECTORY")]
    output: PathBuf,

    /// One printable line recorded in the published package as REVISION.
    #[arg(long, value_name = "TEXT")]
    revision: Option<String>,
}

#[derive(Debug, Args)]
struct TestArgs {
    #[command(flatten)]
    candidate: PackageCandidateArgs,

    /// Absolute runtime configuration for test database access and secret resolution.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute schema-test credential binding document. Required unless --fingerprint-only is given.
    #[arg(
        long,
        value_name = "ABSOLUTE_FILE",
        required_unless_present = "fingerprint_only"
    )]
    credentials: Option<PathBuf>,

    /// New canonical schema-test receipt file. Required unless --fingerprint-only is given.
    #[arg(
        long,
        value_name = "ABSOLUTE_FILE",
        required_unless_present = "fingerprint_only"
    )]
    output: Option<PathBuf>,

    /// Only measure the schema fingerprint a fresh install of the candidate produces, the target a reviewed migration declares. Runs no fixtures and writes no receipt.
    #[arg(
        long,
        conflicts_with_all = ["baseline_package", "reviewed_migrations", "credentials", "output"]
    )]
    fingerprint_only: bool,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    /// Absolute runtime configuration for deployment identity, roles, and database access.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute target package directory.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Activate the first package in an uninitialized Registry database.
    #[arg(long)]
    initial: bool,

    /// Reviewed backup binding the plan requires and the absolute backup binding file that satisfies it, as BINDING_PATH=BINDING_FILE.
    #[arg(long = "backup", value_name = "BINDING_PATH=BINDING_FILE")]
    backups: Vec<String>,

    /// Acknowledge discarding rows retained in a pre-simplification
    /// registry_audit or registry_audit_head table. Without this, apply
    /// refuses rather than silently dropping those retained audit entries
    /// while installing the current schema.
    #[arg(long)]
    acknowledge_retired_audit_discard: bool,

    /// Operator change reference, at most 512 bytes, recorded as a keyed hash in the activation ledger and audit.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: Option<String>,

    /// Package digest the target package must have, as plan and package print it; apply refuses another package before any database contact.
    #[arg(long, value_name = "SHA256_DIGEST", value_parser = parse_expected_digest)]
    expected_digest: Option<String>,
}

#[derive(Debug, Args)]
struct PlanArgs {
    /// Absolute runtime configuration for deployment identity, roles, and database access.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute target package directory.
    #[arg(long, value_name = "ABSOLUTE_DIRECTORY")]
    package: PathBuf,

    /// Reviewed backup binding to verify as apply would, as BINDING_PATH=BINDING_FILE; without it, the plan lists the bindings apply requires.
    #[arg(long = "backup", value_name = "BINDING_PATH=BINDING_FILE")]
    backups: Vec<String>,

    /// Package digest the target package must have, as package prints it; plan refuses another package before any database contact.
    #[arg(long, value_name = "SHA256_DIGEST", value_parser = parse_expected_digest)]
    expected_digest: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// Absolute runtime configuration for deployment identity, roles, and database access.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Absolute Base Registry Engine runtime configuration file.
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
    /// List bounded value-free delivery metadata, including superseded bindings.
    List(WebhookListArgs),
    /// Replay one eligible retained dead-letter using optimistic generation binding.
    Replay(WebhookReplayArgs),
    /// Permanently discard one retained delivery using optimistic generation binding.
    Discard(WebhookDiscardArgs),
}

#[derive(Debug, Subcommand)]
enum RequestRetentionCommand {
    /// List bounded value-free change-request retention rows.
    List(RequestRetentionListArgs),
    /// Count exactly what one request retention erase would remove.
    DryRun(RequestRetentionExactArgs),
    /// Erase eligible payload detail for one exact request proposal version.
    Erase(RequestRetentionExactArgs),
    /// Retry deletion of unreferenced external attachments without erasing request detail.
    CleanupAttachments(AttachmentCleanupArgs),
}

#[derive(Debug, Args)]
struct AttachmentCleanupArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct RequestRetentionListArgs {
    /// Absolute Base Registry Engine runtime configuration file.
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
    /// Absolute Base Registry Engine runtime configuration file.
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
struct ReviewRecoveryArgs {
    #[command(subcommand)]
    command: ReviewRecoveryCommand,
}

#[derive(Debug, Subcommand)]
enum ReviewRecoveryCommand {
    /// Submit the exact retained review request again under its original idempotency key.
    Resubmit(ReviewRecoveryExactArgs),
    /// Close an accepted review without a result so it stops waiting on its authority.
    Close(ReviewRecoveryExactArgs),
    /// Requeue an automatic application blocked by executor authorization after correcting its credentials or grants.
    RetryApplication(ReviewRecoveryExactArgs),
}

#[derive(Debug, Args)]
struct ReviewRecoveryExactArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Compiled change-request entity identifier.
    #[arg(long, value_name = "ENTITY")]
    request_entity: String,

    /// Exact request record UUID.
    #[arg(long, value_name = "UUID")]
    request_id: String,

    /// Exact proposal version whose review or application to recover.
    #[arg(long, value_name = "VERSION")]
    proposal_version: i64,
}

#[derive(Debug, Args)]
struct ImportAuthorityArgs {
    #[command(subcommand)]
    command: ImportAuthorityCommand,
}

#[derive(Debug, Subcommand)]
enum ImportAuthorityCommand {
    /// Open one bounded authority for an `import` grant of the active package.
    Open(ImportAuthorityOpenArgs),
    /// Close one authority; the next chunk of every run under it is blocked.
    Close(ImportAuthorityCloseArgs),
    /// Record every expiry and supersession already due.
    CloseExpired(ImportAuthorityRuntimeArgs),
    /// List the newest authorities, read only, with the status each has reached.
    List(ImportAuthorityRuntimeArgs),
}

#[derive(Debug, Args)]
struct InstanceClaimArgs {
    #[command(subcommand)]
    command: InstanceClaimCommand,
}

#[derive(Debug, Subcommand)]
enum InstanceClaimCommand {
    /// Report the claimed database beside the one the runtime role reaches.
    Status(InstanceClaimStatusArgs),
    /// Make the connected database, such as a restored copy, the one the claim names.
    ///
    /// Run it once after any restore, logical or physical, before the restored
    /// database serves. On a database the claim already names, as after a
    /// point-in-time recovery or a snapshot, it claims the database again and
    /// supersedes every import authority the restore reopened.
    Adopt(InstanceClaimAdoptArgs),
}

#[derive(Debug, Args)]
struct InstanceClaimStatusArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct InstanceClaimAdoptArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Acknowledge that every other copy of this Registry, including the
    /// database the claim names today when it is another one, no longer serves
    /// and never will again.
    ///
    /// Two databases serving one Registry become divergent writers of its
    /// records, import authorities, and outbox work. Without this
    /// flag adoption is refused before any database connection is opened.
    #[arg(long)]
    acknowledge_original_retired: bool,
}

#[derive(Debug, Args)]
struct ImportAuthorityOpenArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Entity the authority admits creates for.
    #[arg(long, value_name = "ENTITY")]
    entity: String,

    /// Access profile holding the entity's `import` grant.
    #[arg(long, value_name = "PROFILE")]
    profile: String,

    /// Most records every run under the authority may create, together.
    #[arg(long, value_name = "COUNT")]
    max_items: i64,

    /// How long the authority stays open: whole minutes, hours, or days
    /// (`90m`, `12h`, `7d`), at most 30 days. There is no extension.
    #[arg(long, value_name = "DURATION", default_value = "7d")]
    expires_in: String,

    /// SHA-256 input digest a run must announce, as `bregctl data validate`
    /// reports it. The client computes it and the run records it; the server
    /// does not recompute it over the written items. Repeat to allow several;
    /// omit to admit any.
    #[arg(long = "input-sha256", value_name = "SHA256")]
    input_sha256: Vec<String>,

    /// Operator change reference recorded as a keyed hash.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: String,

    /// Reason recorded as a keyed hash, never in clear.
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Debug, Args)]
struct ImportAuthorityCloseArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Identifier `import-authority open` reported.
    #[arg(long, value_name = "UUID")]
    authority_id: String,

    /// Operator change reference recorded as a keyed hash.
    #[arg(long, value_name = "REFERENCE")]
    operator_reference: String,

    /// Reason recorded as a keyed hash, never in clear.
    #[arg(long, value_name = "TEXT")]
    reason: String,
}

#[derive(Debug, Args)]
struct ImportAuthorityRuntimeArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct WebhookSampleArgs {
    /// Base Registry Engine authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Stable authored event identifier.
    #[arg(long, value_name = "ID")]
    event: String,
}

#[derive(Debug, Args)]
struct WebhookListArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Maximum number of value-free delivery rows to return.
    #[arg(long, value_name = "COUNT", default_value_t = 50)]
    limit: u16,
}

#[derive(Debug, Args)]
struct WebhookReplayArgs {
    /// Absolute Base Registry Engine runtime configuration file.
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

#[derive(Debug, Args)]
struct WebhookDiscardArgs {
    /// Absolute Base Registry Engine runtime configuration file.
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

    /// Base Registry Engine base URL. HTTP is accepted only for loopback hosts.
    #[arg(long, value_name = "URL")]
    breg_url: String,

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

    /// Base Registry Engine base URL. HTTP is accepted only for loopback hosts.
    #[arg(long, value_name = "URL")]
    breg_url: String,

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

    /// JSON Lines output file. Existing output resumes from its checkpoint.
    ///
    /// A resume continues after the last page the checkpoint records and
    /// discards the output beyond it, which is at most the one page a run
    /// stopped between appending a page and publishing its checkpoint left
    /// behind. A longer tail is refused rather than discarded. The output and
    /// the checkpoint are usable only as a pair: one present without the other
    /// is refused, and removing the file that remains starts a fresh export.
    /// A path holding a `..` component is refused.
    #[arg(long, value_name = "FILE")]
    output: PathBuf,

    /// Export checkpoint file written after every page.
    ///
    /// The checkpoint is published after the page it records reaches the
    /// output, so it names the position a resume continues from. Keep it for
    /// as long as the output it belongs to, and give each export its own pair.
    /// A path holding a `..` component is refused.
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

impl From<DataOperationArg> for registry_breg::data::DataImportOperation {
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
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,
}

#[derive(Debug, Args)]
struct MigrationReconcileArgs {
    /// Absolute Base Registry Engine runtime configuration file.
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
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute owner-only JSON erasure request file.
    ///
    /// Read through the parent directory this path resolves to, so a `..`
    /// component is refused. The file must carry no group or other permission
    /// bits, because it names the records the erasure covers.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    request_file: PathBuf,

    /// Acknowledge that erasure cannot be undone.
    ///
    /// Without this flag the command is refused before any file is read or
    /// any database connection is opened.
    #[arg(long)]
    acknowledge_irreversible: bool,
}

#[derive(Debug, Args)]
struct HistoryRebaselineArgs {
    /// Absolute Base Registry Engine runtime configuration file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    runtime_config: PathBuf,

    /// Absolute owner-only JSON rebaseline request file.
    ///
    /// Read through the parent directory this path resolves to, so a `..`
    /// component is refused. The file must carry no group or other permission
    /// bits, because it names the records the rebaseline covers.
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
    /// Base Registry Engine authoring project directory.
    #[arg(value_name = "PROJECT")]
    project: PathBuf,

    /// Absolute runtime configuration whose configured package is the baseline.
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
    EvidenceSource,
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
    Lifecycle,
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
    /// Absent for `explain lifecycle`, the one report no project produces,
    /// and for a `module add consent` whose project compiles only once a
    /// profile requires consent. Every other command compiles a project and
    /// names its revision here.
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    /// Named only by `check`: the registry revision it compiled from a
    /// project or rederived from a verified package, the value a Casework
    /// BReg source description pins as its `sourceRevision`.
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_revision: Option<String>,
    /// Named only by `check --package`: the digest of the package it verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    package_digest: Option<String>,
    #[serde(serialize_with = "serialize_findings")]
    findings: Vec<ToolDiagnostic>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<ArtifactReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<Value>,
    /// What the reader does next, in the order a reader does it.
    ///
    /// A command that leaves the reader holding something unfinished says so
    /// here, so the sentence travels with the report instead of living only in
    /// a tutorial the reader may not be following.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    next_steps: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlannerTestSuccessReport {
    ok: bool,
    command: &'static str,
    compiled_revision: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    request_entity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refusal: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assertions_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    planner: Option<PlannerTestIdentityReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    handler: Option<PlannerTestIdentityReport>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldEncryptionKeygenSuccessReport<'a> {
    ok: bool,
    command: &'static str,
    output: &'a str,
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

/// A successful report already identifies these entries as `findings`, so its
/// elements do not repeat the constant `finding` severity. Refusal reports keep
/// the complete diagnostic envelope because they can contain findings or errors.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolFinding<'a> {
    code: &'a str,
    artifact: DiagnosticArtifact,
    path: &'a str,
    message: &'a str,
    suggested_action: SuggestedAction,
}

fn serialize_findings<S>(findings: &[ToolDiagnostic], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    findings
        .iter()
        .map(|finding| ToolFinding {
            code: &finding.code,
            artifact: finding.artifact,
            path: &finding.path,
            message: &finding.message,
            suggested_action: finding.suggested_action,
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticArtifact {
    CommandArguments,
    RegistryProject,
    ProjectInitialization,
    ModelSelection,
    GeneratedArtifacts,
    CompiledInventory,
    RuntimeConfiguration,
    BaselinePackage,
    CompiledDiff,
    PackageBuild,
    SchemaTestReceipt,
    SchemaTestCandidate,
    FixtureJourneys,
    SchemaTestCredentials,
    SchemaTestDatabase,
    SchemaTestExecution,
    SchemaTestOutput,
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
    ReviewRecoveryOperation,
    EvidenceRetentionOperation,
    ImportAuthority,
    InstanceClaim,
    HistoryErasure,
    HistoryRebaseline,
    FieldEncryption,
    PlannerTest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SuggestedAction {
    CorrectCommandUsage,
    CorrectAuthoringSource,
    ReviewAuthoringFinding,
    ChooseSafeOutputDirectory,
    CorrectModelSelection,
    SelectAvailableArtifact,
    RetryArtifactGeneration,
    RetryInventoryExplanation,
    UpdateModuleLocks,
    CorrectRuntimeConfiguration,
    VerifyPackagePath,
    VerifyPackagePermissions,
    VerifyPackageBinding,
    VerifyPackageIntegrity,
    RerunPlanOnIntendedPackage,
    ReviewCompiledDiff,
    CorrectPackageBuild,
    SupplySchemaTestReceipt,
    CorrectSchemaTestCandidate,
    CorrectFixtureJourneys,
    SupplySchemaTestCredentials,
    PrepareSchemaTestDatabase,
    RecreateDisposableDatabase,
    ChooseSchemaTestOutput,
    VerifyMigrationAuthority,
    RetryAfterMigrationLockReleases,
    ReconcileFailedMigration,
    RestorePreActivationBackup,
    ResolveActiveRequestProposals,
    ArchiveRetiredAuditRows,
    VerifyStartupDependencies,
    CorrectDataBinding,
    CorrectDataInput,
    VerifyDataCheckpoint,
    VerifyDataTransport,
    SelectWebhookEvent,
    VerifyWebhookOperation,
    VerifyRequestRetentionOperation,
    VerifyReviewRecoveryOperation,
    VerifyEvidenceRetentionOperation,
    CorrectImportAuthorityRequest,
    VerifyImportAuthority,
    VerifyInstanceClaim,
    PrepareHistoryErasureRequest,
    PrepareHistoryRebaselineRequest,
    ReviewRetainedHistory,
    ReviewFieldEncryptionBackfill,
    PrepareFieldEncryptionEraseRequest,
    CorrectPlannerTestInput,
    CorrectActionHandler,
    RunSchemaTest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorSuccessReport<'a> {
    ok: bool,
    command: &'static str,
    checked: &'static [&'static str],
    role_mode: &'static str,
    advisories: Vec<DoctorAdvisory<'a>>,
}

/// What one-role mode guards and what it does not, said wherever the role
/// mode is reported.
const SINGLE_ROLE_MODE_NOTE: &str = "the runtime serves with the migration role; the activation \
     ledger check catches mistakes but not someone holding that credential";

/// One PostgreSQL baseline advisory as doctor reports it. Advisories never
/// change the outcome: doctor passed before they were decided.
#[derive(Serialize)]
struct DoctorAdvisory<'a> {
    code: &'static str,
    severity: &'static str,
    message: &'static str,
    observed: ObservedNumbers<'a>,
}

/// The observed numbers of one advisory, as a JSON object in the order the
/// advisory decided them.
struct ObservedNumbers<'a>(&'a [(&'static str, i64)]);

impl Serialize for ObservedNumbers<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifySuccessReport {
    ok: bool,
    command: &'static str,
    assurance: BaselineAssurance,
    package_digest: String,
    registry: VerifiedRegistryReport,
    inventory: VerifiedInventoryReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationExplainSuccessReport {
    ok: bool,
    command: &'static str,
    assurance: BaselineAssurance,
    package_digest: String,
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
struct FieldEncryptionPreflightSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: FieldEncryptionPreflightLifecycleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FieldEncryptionEraseHistorySuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: FieldEncryptionEraseHistoryLifecycleOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PackageSuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    package_digest: String,
    registry_revision: String,
    package_files: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaTestSuccessReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    registry_revision: String,
    schema_fingerprint: String,
    successful_journey_ids: Vec<String>,
    receipt: ArtifactReport,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<Diagnostic>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaFingerprintReport {
    ok: bool,
    command: &'static str,
    profile: ProfileArg,
    registry_revision: String,
    schema_fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplySuccessReport {
    ok: bool,
    command: &'static str,
    activation: ApplyActivation,
    package_digest: String,
    schema_fingerprint: String,
    activation_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanSuccessReport {
    ok: bool,
    command: &'static str,
    /// Whether `bregctl apply` would record an activation.
    pending: bool,
    activation: PlanActivation,
    package_digest: String,
    registry_revision: String,
    active_package_digest: Option<String>,
    role_mode: &'static str,
    resumes_activation_id: Option<String>,
    required_backups: Vec<String>,
    checks: &'static [&'static str],
    migration: MigrationInspectionSummary,
}

/// The activation `bregctl apply` would report, or `none` when the package is
/// already active with the configured roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PlanActivation {
    Initial,
    Successor,
    RoleChange,
    None,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusSuccessReport {
    ok: bool,
    command: &'static str,
    package_id: String,
    database_id: String,
    active_package_digest: String,
    activation_id: String,
    registry_revision: Option<String>,
    role_mode: Option<String>,
    schema_fingerprint: String,
    maintenance_status: String,
    maintenance_target_package_digest: Option<String>,
    ledger: Vec<StatusLedgerEntry>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusLedgerEntry {
    activation_id: String,
    apply_order: i64,
    package_digest: String,
    predecessor_package_digest: Option<String>,
    registry_revision: String,
    plan_kind: String,
    migration_kind: String,
    outcome: String,
    role_mode: String,
    started_at: String,
    completed_at: Option<String>,
    applied_at: Option<String>,
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
    input_digest: String,
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
    run_id: String,
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
struct WebhookDiscardSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: WebhookDiscardOutcome,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewRecoverySuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: ReviewRecoveryOutcome,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentCleanupSuccessReport {
    ok: bool,
    command: &'static str,
    #[serde(flatten)]
    outcome: registry_breg::request_retention::AttachmentCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApplyActivation {
    Initial,
    Successor,
    RoleChange,
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
    #[serde(serialize_with = "serialize_findings")]
    findings: Vec<ToolDiagnostic>,
    #[serde(flatten)]
    diff: CompiledRegistryDiff,
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
    compiler_source_revision: String,
    from_package_digest: Option<String>,
    project: PackageSourceFile,
    project_assets: Vec<PackageSourceFile>,
    modules: Vec<PackageModuleSource>,
    fixture_journeys: PackageSourceFile,
    migration_plan: PackageMigrationPlanInput,
    prevalidation_schema_fingerprint: Option<String>,
    rehearsal_baseline: Option<RehearsalBaseline>,
}

/// The verified predecessor a successor candidate is rehearsed over: its
/// registry compiled from the packaged sources and the schema fingerprint its
/// manifest binds.
#[derive(Clone, Debug)]
struct RehearsalBaseline {
    registry: CompiledRegistry,
    schema_fingerprint: String,
}

impl CapturedPackageCandidate {
    fn registry(&self) -> &CompiledRegistry {
        &self.compiled
    }

    fn fixture_journeys(&self) -> &[u8] {
        &self.fixture_journeys.bytes
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
        registry_breg::package::prepare_package_with_project_assets(
            PackageBuildRequest {
                from_package_digest: self.from_package_digest,
                compiler_source_revision: self.compiler_source_revision,
                schema_fingerprint,
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
///
/// The process streams are wrapped so the renderers can write the ANSI
/// attributes unconditionally: `AutoStream` keeps them when the destination is
/// a terminal and strips them when it is a pipe, a file, or a test harness,
/// honoring `NO_COLOR` and `CLICOLOR_FORCE` on the way. A tutorial that
/// captures a command therefore records the same plain bytes it prints.
pub fn main_entry() -> ExitCode {
    // Every PostgreSQL session this process opens names it, so an operator can
    // tell tooling sessions from the runtime's in `pg_stat_activity`. Nothing
    // has connected yet, so the name cannot already be fixed to another one.
    registry_breg::postgres::set_application_name("bregctl")
        .expect("bregctl names its PostgreSQL sessions before opening any");
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut stdout = AutoStream::new(stdout, AutoStream::choice(&io::stdout()));
    let mut stderr = AutoStream::new(stderr, AutoStream::choice(&io::stderr()));
    run_from(std::env::args_os(), &mut stdout, &mut stderr)
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
    if machine_mode && help_requested(&arguments) {
        let catalog = registry_cli_reference::binary_catalog(
            command(),
            registry_platform_buildinfo::DISPLAY_VERSION,
            Some(registry_cli_reference::SYMBOLIC_LINK_REFUSAL),
        );
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string(&catalog).expect("the command catalog serializes")
        );
        return ExitCode::SUCCESS;
    }
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
            let message = usage_message(&error, &arguments);
            if !machine_mode {
                let _ = writeln!(stderr, "error: {message}");
                return ExitCode::from(USAGE_EXIT);
            }
            let report = FailureReport {
                ok: false,
                command: "usage",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("usage.invalid", "arguments", &message),
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
        Command::Examples(args) => {
            return match dev::examples::run(args) {
                Ok(report) => write_examples_success(&report, format, stdout, stderr),
                Err(error) => write_failure(
                    &source_failure(
                        "examples",
                        diagnostic("examples.failed", "examples", &format!("{error:#}")),
                        DiagnosticArtifact::CommandArguments,
                        SuggestedAction::CorrectCommandUsage,
                    ),
                    format,
                    stdout,
                    stderr,
                ),
            };
        }
        Command::Dev(args) => {
            return match dev::run(args) {
                Ok(report) => write_dev_success(&report, format, stdout, stderr),
                Err(error) => write_failure(
                    &source_failure(
                        "dev",
                        diagnostic("dev.failed", "dev", &format!("{error:#}")),
                        DiagnosticArtifact::CommandArguments,
                        SuggestedAction::CorrectCommandUsage,
                    ),
                    format,
                    stdout,
                    stderr,
                ),
            };
        }
        Command::DevSupervisor(args) => {
            return match dev::run_supervisor(args) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    let _ = writeln!(stderr, "{error:#}");
                    ExitCode::from(OPERATIONAL_FAILURE_EXIT)
                }
            };
        }
        Command::Init(args) => match (args.from, args.template.as_deref()) {
            (None, None) => init(&args.destination),
            (None, Some(id)) => starters::run(&args.destination, id),
            (Some(model), None) => {
                let source = match (&args.selection, &args.starter) {
                    (Some(path), _) => init_from_model::Source::File(path),
                    (None, Some(name)) => init_from_model::Source::Starter(name),
                    (None, None) => init_from_model::Source::Interactive,
                };
                init_from_model::run(&args.destination, model, source)
            }
            (Some(_), Some(_)) => unreachable!("clap refuses --from together with --template"),
        },
        Command::Check(args) => match (&args.project, &args.package) {
            (Some(project), None) => check(project, profile(args.production)),
            (None, Some(package)) => check_package(package),
            _ => unreachable!("clap enforces exactly one of a project and a package"),
        }
        .and_then(|report| {
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
        Command::Module(args) => match args.command {
            ModuleCommand::Add(args) => match args.module {
                ModuleAddCommand::Consent(args) => {
                    consent_module::add_consent_module(&args.project, &args.subject)
                }
            },
        },
        Command::Project(args) => match args.command {
            ProjectCommand::Lock(args) => project_lock(&args.project, args.check),
            ProjectCommand::PlannerTest(args) => {
                return match planner_test(&args) {
                    Ok(report) => write_planner_test_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                };
            }
        },
        Command::Generate(args) => generate_requested(&args),
        Command::Explain(args) => explain(
            args.subject,
            args.project.as_deref(),
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
        Command::Test(args) if args.fingerprint_only => {
            return match measure_schema_fingerprint(&args) {
                Ok(report) => write_schema_fingerprint(&report, format, stdout, stderr),
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
        Command::Plan(args) => {
            return match plan(&args) {
                Ok(report) => write_plan_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Status(args) => {
            return match status(&args) {
                Ok(report) => write_status_success(&report, format, stdout, stderr),
                Err(failure) => write_failure(&failure, format, stdout, stderr),
            };
        }
        Command::Doctor(args) => {
            return match doctor::run(&args.runtime_config) {
                Ok(checked) => write_doctor_success(
                    &checked.postgres_advisories,
                    checked.role_mode,
                    format,
                    stdout,
                    stderr,
                ),
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
                WebhookCommand::Discard(args) => match webhook_discard(&args) {
                    Ok(report) => write_webhook_discard_success(&report, format, stdout, stderr),
                    Err(failure) => write_failure(&failure, format, stdout, stderr),
                },
            };
        }
        Command::EvidenceRetention(args) => {
            let EvidenceRetentionCommand::EraseExpired(args) = args.command;
            let outcome = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| registry_breg::mutation::MutationError::Unavailable)
                .and_then(|runtime| {
                    runtime.block_on(registry_breg::action_evidence_maintenance::erase_expired(
                        &args.runtime_config,
                        &args.before,
                    ))
                });
            return match outcome {
                Ok(erased) => {
                    let result = if format == OutputFormat::Json {
                        serde_json::to_writer_pretty(&mut *stdout, &json!({"ok":true,"command":"evidence-retention erase-expired","erased":erased}))
                            .map_err(io::Error::other).and_then(|()| writeln!(stdout))
                    } else {
                        render_report(
                            "Erased expired action Evidence.",
                            &[("erased", erased.to_string())],
                            stdout,
                        )
                    };
                    write_result(result, stderr)
                }
                Err(error) => {
                    write_failure(&evidence_retention_failure(error), format, stdout, stderr)
                }
            };
        }
        Command::ReviewRecovery(args) => {
            let (command, operation, args) = match args.command {
                ReviewRecoveryCommand::Resubmit(args) => (
                    "review-recovery resubmit",
                    ReviewRecoveryOperation::Resubmit,
                    args,
                ),
                ReviewRecoveryCommand::Close(args) => (
                    "review-recovery close",
                    ReviewRecoveryOperation::Close,
                    args,
                ),
                ReviewRecoveryCommand::RetryApplication(args) => (
                    "review-recovery retry-application",
                    ReviewRecoveryOperation::RetryApplication,
                    args,
                ),
            };
            return match review_recovery::recover(
                operation,
                &args.runtime_config,
                &args.request_entity,
                &args.request_id,
                args.proposal_version,
            ) {
                Ok(outcome) => write_review_recovery_success(
                    &ReviewRecoverySuccessReport {
                        ok: true,
                        command,
                        outcome,
                    },
                    format,
                    stdout,
                    stderr,
                ),
                Err(error) => write_failure(
                    &review_recovery_failure(command, error),
                    format,
                    stdout,
                    stderr,
                ),
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
                RequestRetentionCommand::CleanupAttachments(args) => {
                    match request_retention::cleanup_attachments(&args.runtime_config) {
                        Ok(outcome) => write_attachment_cleanup_success(
                            &AttachmentCleanupSuccessReport {
                                ok: true,
                                command: "request-retention cleanup-attachments",
                                outcome,
                            },
                            format,
                            stdout,
                            stderr,
                        ),
                        Err(error) => write_failure(
                            &request_retention_failure(
                                "request-retention cleanup-attachments",
                                error,
                            ),
                            format,
                            stdout,
                            stderr,
                        ),
                    }
                }
            };
        }
        Command::ImportAuthority(args) => {
            let (command, outcome) = match args.command {
                ImportAuthorityCommand::Open(args) => (
                    "import-authority open",
                    import_authority_lifecycle::open(&import_authority_lifecycle::OpenArguments {
                        runtime_config: &args.runtime_config,
                        entity: &args.entity,
                        profile: &args.profile,
                        max_items: args.max_items,
                        expires_in: &args.expires_in,
                        input_sha256: &args.input_sha256,
                        operator_reference: &args.operator_reference,
                        reason: &args.reason,
                    })
                    .map(|authority| vec![authority]),
                ),
                ImportAuthorityCommand::Close(args) => (
                    "import-authority close",
                    import_authority_lifecycle::close(
                        &import_authority_lifecycle::CloseArguments {
                            runtime_config: &args.runtime_config,
                            authority_id: &args.authority_id,
                            operator_reference: &args.operator_reference,
                            reason: &args.reason,
                        },
                    )
                    .map(|authority| vec![authority]),
                ),
                ImportAuthorityCommand::CloseExpired(args) => (
                    "import-authority close-expired",
                    import_authority_lifecycle::close_expired(&args.runtime_config),
                ),
                ImportAuthorityCommand::List(args) => (
                    "import-authority list",
                    import_authority_lifecycle::list(&args.runtime_config),
                ),
            };
            return match outcome {
                Ok(authorities) => {
                    write_import_authority_success(command, &authorities, format, stdout, stderr)
                }
                Err(error) => write_failure(
                    &import_authority_failure(command, error),
                    format,
                    stdout,
                    stderr,
                ),
            };
        }
        Command::InstanceClaim(args) => {
            return match args.command {
                InstanceClaimCommand::Status(args) => {
                    match instance_claim_lifecycle::status(&args.runtime_config) {
                        Ok(status) => write_instance_claim_status(&status, format, stdout, stderr),
                        Err(error) => write_failure(
                            &instance_claim_failure("instance-claim status", error),
                            format,
                            stdout,
                            stderr,
                        ),
                    }
                }
                InstanceClaimCommand::Adopt(args) => {
                    if !args.acknowledge_original_retired {
                        return write_failure(
                            &instance_claim_acknowledgement_required(),
                            format,
                            stdout,
                            stderr,
                        );
                    }
                    match instance_claim_lifecycle::adopt(&args.runtime_config) {
                        Ok(adoption) => {
                            write_instance_claim_adoption(&adoption, format, stdout, stderr)
                        }
                        Err(error) => write_failure(
                            &instance_claim_failure("instance-claim adopt", error),
                            format,
                            stdout,
                            stderr,
                        ),
                    }
                }
            };
        }
        Command::FieldEncryption(args) => {
            return match args.command {
                FieldEncryptionCommand::Keygen(args) => {
                    match field_encryption::keygen(&args.output) {
                        Ok(outcome) => {
                            write_field_encryption_keygen_success(&outcome, format, stdout, stderr)
                        }
                        Err(failure) => write_failure(
                            &field_encryption_keygen_failure(failure),
                            format,
                            stdout,
                            stderr,
                        ),
                    }
                }
                FieldEncryptionCommand::Preflight(args) => {
                    match field_encryption_preflight(&args) {
                        Ok(report) => write_field_encryption_preflight_success(
                            &report, format, stdout, stderr,
                        ),
                        Err(failure) => write_failure(&failure, format, stdout, stderr),
                    }
                }
                FieldEncryptionCommand::EraseHistory(args) => {
                    match field_encryption_erase_history(&args) {
                        Ok(report) => write_field_encryption_erase_history_success(
                            &report, format, stdout, stderr,
                        ),
                        Err(failure) => write_failure(&failure, format, stdout, stderr),
                    }
                }
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

fn evidence_retention_failure(error: registry_breg::mutation::MutationError) -> FailureReport {
    let command = "evidence-retention erase-expired";
    match error {
        registry_breg::mutation::MutationError::MigrationLockHeld => source_failure(
            command,
            diagnostic(
                "evidence_retention.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Nothing was erased. Retry the same erasure once it releases",
            ),
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::RetryAfterMigrationLockReleases,
        ),
        registry_breg::mutation::MutationError::PackagePinMismatch(mismatch) => package_pin_failure(
            command,
            "evidence_retention.package.refused",
            "package",
            &mismatch,
        ),
        _ => source_failure(
            command,
            diagnostic(
                "evidence_retention.unavailable",
                "evidenceRetention",
                "Verify the absolute runtime configuration, migration authority and nonfuture RFC 3339 cutoff.",
            ),
            DiagnosticArtifact::EvidenceRetentionOperation,
            SuggestedAction::VerifyEvidenceRetentionOperation,
        ),
    }
}

fn request_retention_failure(
    command: &'static str,
    error: RequestRetentionCliError,
) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        RequestRetentionCliError::PackagePinMismatch(mismatch) => {
            return package_pin_failure(
                command,
                "request_retention.package.refused",
                "package",
                &mismatch,
            )
        }
        RequestRetentionCliError::MigrationLockHeld => (
            "request_retention.in_progress",
            "database",
            "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. A detail erasure that committed before the wait stays erased, which `request-retention dry-run` shows. Retry the same operation once it releases",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::RetryAfterMigrationLockReleases,
        ),
        RequestRetentionCliError::Operator => (
            "request_retention.operation.refused",
            "requestRetention",
            "the request retention operation was refused",
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
        ),
        RequestRetentionCliError::ActiveDetailPinned => (
            "request_retention.detail.pinned",
            "requestRetention",
            "active request detail is still pinned",
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
        ),
        RequestRetentionCliError::RetainMode => (
            "request_retention.mode.retain",
            "requestRetention",
            "the request retention policy does not permit operator erasure",
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
        ),
        RequestRetentionCliError::ErasureUnaudited => (
            "request_retention.erasure.unaudited",
            "requestRetention",
            "the erasure committed but its audit entry was not recorded; restore the audit destination, then reconcile the erased request against the database",
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
        ),
        RequestRetentionCliError::AttachmentStorageBindingMismatch => (
            "request_retention.attachment_storage.binding_mismatch",
            "requestRetention",
            "restore the original attachment storage binding and verification policy before retrying; the registry pin, retained content, or deletion tombstones still require them",
            DiagnosticArtifact::RequestRetentionOperation,
            SuggestedAction::VerifyRequestRetentionOperation,
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

fn review_recovery_failure(command: &'static str, error: ReviewRecoveryCliError) -> FailureReport {
    let (code, message) = match error {
        ReviewRecoveryCliError::Operator => (
            "review_recovery.operation.refused",
            "the review recovery operation was refused; verify the absolute runtime configuration, migration authority, request UUID and positive proposal version".to_owned(),
        ),
        ReviewRecoveryCliError::NotFound => (
            "review_recovery.submission.not_found",
            "no retained review submission or application job exists for this exact request proposal version".to_owned(),
        ),
        ReviewRecoveryCliError::Ineligible {
            reason,
            state,
            code,
        } => (
            "review_recovery.submission.ineligible",
            format!(
                "the retained review or application does not accept this operation: reason {reason}, state {state}, code {}",
                code.as_deref().unwrap_or("none")
            ),
        ),
        ReviewRecoveryCliError::RecoveryUnaudited => (
            "review_recovery.recovery.unaudited",
            "the review recovery committed but its audit entry was not recorded; restore the audit destination, then read the submission's state from the database before retrying".to_owned(),
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, "reviewRecovery", &message),
            DiagnosticArtifact::ReviewRecoveryOperation,
            SuggestedAction::VerifyReviewRecoveryOperation,
        )],
    }
}

fn import_authority_failure(
    command: &'static str,
    error: ImportAuthorityCliError,
) -> FailureReport {
    use registry_breg::import_authority::ImportAuthorityError;
    let (failure_diagnostic, artifact, action) = match error {
        ImportAuthorityCliError::RuntimeConfigPath => (
            diagnostic(
                "import_authority.runtime_config.invalid",
                "runtimeConfig",
                "the runtime configuration must be an absolute path",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::CorrectCommandUsage,
        ),
        ImportAuthorityCliError::ExpiresIn => (
            diagnostic(
                "import_authority.expires_in.invalid",
                "expiresIn",
                "the authority window must be a whole number of minutes, hours, or days (for example 90m, 12h, or 7d), from one minute to at most 30 days",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::CorrectImportAuthorityRequest,
        ),
        ImportAuthorityCliError::AuthorityId => (
            diagnostic(
                "import_authority.authority_id.invalid",
                "authorityId",
                "the authority identifier must be the UUID `import-authority open` or `import-authority list` reported",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::CorrectImportAuthorityRequest,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::InvalidInput) => (
            diagnostic(
                "import_authority.request.invalid",
                "importAuthority",
                "the request is out of bounds: the entity, profile, operator reference, and reason must be present and free of control characters, the volume at least one, and each pinned input digest 64 lowercase hexadecimal characters, named once, at most 16",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::CorrectImportAuthorityRequest,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::NotImportable) => (
            diagnostic(
                "import_authority.grant.not_importable",
                "entity",
                "the entity and profile do not name an `import` grant of the active package; check them with `bregctl explain access`",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::CorrectImportAuthorityRequest,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::AlreadyOpen) => (
            diagnostic(
                "import_authority.already_open",
                "entity",
                "an import authority is already open for this entity; close it with `bregctl import-authority close` before opening another",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::VerifyImportAuthority,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::NotFound) => (
            diagnostic(
                "import_authority.not_found",
                "authorityId",
                "no import authority has this identifier; `bregctl import-authority list` names the recorded ones",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::VerifyImportAuthority,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::NotReady) => (
            diagnostic(
                "import_authority.not_ready",
                "importAuthority",
                "the registry is not ready for import authority maintenance; apply the configured package first",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::VerifyImportAuthority,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::PackagePinMismatch(mismatch)) => {
            return package_pin_failure(
                command,
                "import_authority.package.refused",
                "package",
                &mismatch,
            )
        }
        ImportAuthorityCliError::Authority(ImportAuthorityError::MigrationLockHeld) => (
            diagnostic(
                "import_authority.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. No authority changed. Retry the same command once it releases",
            ),
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::RetryAfterMigrationLockReleases,
        ),
        ImportAuthorityCliError::Authority(ImportAuthorityError::Unavailable) => (
            diagnostic(
                "import_authority.unavailable",
                "importAuthority",
                "the import authority store is unavailable; verify the runtime configuration, the migration authority, the active package binding, and a keyed audit profile",
            ),
            DiagnosticArtifact::ImportAuthority,
            SuggestedAction::VerifyImportAuthority,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(failure_diagnostic, artifact, action)],
    }
}

fn instance_claim_acknowledgement_required() -> FailureReport {
    FailureReport {
        ok: false,
        command: "instance-claim adopt",
        diagnostics: vec![tool_diagnostic(
            diagnostic(
                "instance_claim.acknowledgement.required",
                "acknowledgeOriginalRetired",
                "adopting makes this database the only one that serves the Registry, and two databases serving one Registry become divergent writers of it: stop and retire every other copy, including the database the claim names when it is another one, then pass --acknowledge-original-retired",
            ),
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        )],
    }
}

fn instance_claim_failure(command: &'static str, error: InstanceClaimCliError) -> FailureReport {
    use registry_breg::instance_claim::InstanceClaimError;
    let (failure_diagnostic, artifact, action) = match error {
        InstanceClaimCliError::RuntimeConfigPath => (
            diagnostic(
                "instance_claim.runtime_config.invalid",
                "runtimeConfig",
                "the runtime configuration must be an absolute path",
            ),
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        ),
        InstanceClaimCliError::Claim(InstanceClaimError::Unavailable) => (
            diagnostic(
                "instance_claim.unavailable",
                "instanceClaim",
                "the instance claim is unavailable; verify the runtime configuration, both database roles, the active package binding, and a keyed audit profile, and apply the package if the claim table is not yet installed",
            ),
            DiagnosticArtifact::InstanceClaim,
            SuggestedAction::VerifyInstanceClaim,
        ),
        InstanceClaimCliError::Claim(InstanceClaimError::MigrationLockHeld) => (
            diagnostic(
                "instance_claim.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Nothing was adopted and no authority was superseded. Retry the same adoption once it releases",
            ),
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::RetryAfterMigrationLockReleases,
        ),
        InstanceClaimCliError::Claim(InstanceClaimError::PackageRefused(message)) => (
            diagnostic("instance_claim.package.refused", "package", &message),
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackageBinding,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(failure_diagnostic, artifact, action)],
    }
}

/// A system identifier the role could not read is named as such, so the
/// operator sees that the claim compares the database oid alone.
fn system_identifier_text(value: Option<&str>) -> String {
    value.map_or_else(
        || "not readable (the claim compares the database oid alone)".to_owned(),
        str::to_owned,
    )
}

fn instance_claim_pairs(
    claim: &registry_breg::instance_claim::InstanceClaim,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "system identifier",
            system_identifier_text(claim.identity.system_identifier.as_deref()),
        ),
        ("database oid", claim.identity.database_oid.to_string()),
        ("epoch", claim.epoch.to_string()),
        ("claimed at", claim.claimed_at.to_rfc3339()),
    ]
}

fn write_instance_claim_status(
    status: &registry_breg::instance_claim::InstanceClaimStatus,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        let body = json!({"ok": true, "command": "instance-claim status", "status": status});
        serde_json::to_writer_pretty(&mut *stdout, &body)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let lead = match (&status.claim, status.matches) {
            (_, true) => "The instance claim names this database.",
            (Some(_), false) => {
                "The instance claim names another database. Once that database is retired, adopt this one with bregctl instance-claim adopt."
            }
            (None, false) => {
                "No instance claim is recorded. Claim this database with bregctl instance-claim adopt."
            }
        };
        let mut lines = report::Lines::new();
        lines.lead(lead);
        lines.blank();
        lines.pairs(&[
            (
                "this database system identifier",
                system_identifier_text(status.live.system_identifier.as_deref()),
            ),
            ("this database oid", status.live.database_oid.to_string()),
        ]);
        if let Some(claim) = &status.claim {
            lines.blank();
            lines.pairs(&instance_claim_pairs(claim));
        }
        stdout.write_all(lines.finish().as_bytes())
    };
    write_result(result, stderr)
}

fn write_instance_claim_adoption(
    adoption: &registry_breg::instance_claim::InstanceClaimAdoption,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        let body = json!({"ok": true, "command": "instance-claim adopt", "adoption": adoption});
        serde_json::to_writer_pretty(&mut *stdout, &body)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let mut lines = report::Lines::new();
        lines.lead(&format!(
            "Adopted this database. The instance claim is at epoch {}.",
            adoption.current.epoch
        ));
        lines.blank();
        lines.pairs(&instance_claim_pairs(&adoption.current));
        if !adoption.superseded_import_authorities.is_empty() {
            lines.heading(
                "Superseded import authorities the copy carried open; open a new one before importing again",
            );
            for authority_id in &adoption.superseded_import_authorities {
                lines.bullet(&authority_id.to_string());
            }
        }
        stdout.write_all(lines.finish().as_bytes())
    };
    write_result(result, stderr)
}

fn write_import_authority_success(
    command: &'static str,
    authorities: &[registry_breg::import_authority::ImportAuthority],
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        let body = match command {
            "import-authority open" | "import-authority close" => {
                json!({"ok": true, "command": command, "authority": authorities.first()})
            }
            _ => json!({"ok": true, "command": command, "authorities": authorities}),
        };
        serde_json::to_writer_pretty(&mut *stdout, &body)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let lead = match command {
            "import-authority open" => "Opened the import authority.".to_owned(),
            "import-authority close" => "Recorded the import authority's final state.".to_owned(),
            "import-authority close-expired" => format!(
                "Recorded the due import authority transitions. {}.",
                report::counted(authorities.len(), "authority")
            ),
            _ => format!(
                "Listed the newest import authorities. {}.",
                report::counted(authorities.len(), "authority")
            ),
        };
        let mut lines = report::Lines::new();
        lines.lead(&lead);
        for authority in authorities {
            lines.blank();
            lines.pairs(&import_authority_pairs(authority));
        }
        stdout.write_all(lines.finish().as_bytes())
    };
    write_result(result, stderr)
}

fn import_authority_pairs(
    authority: &registry_breg::import_authority::ImportAuthority,
) -> Vec<(&'static str, String)> {
    let mut pairs = vec![
        ("authority id", authority.authority_id.to_string()),
        ("status", authority.status.as_str().to_owned()),
        ("entity", authority.entity_id.clone()),
        ("profile", authority.profile_id.clone()),
        (
            "committed items",
            format!("{} of {}", authority.committed_items, authority.max_items),
        ),
        ("activation id", authority.activation_id.to_string()),
        ("opened at", authority.opened_at.to_rfc3339()),
        ("expires at", authority.expires_at.to_rfc3339()),
    ];
    if let Some(closed_at) = authority.closed_at {
        pairs.push(("closed at", closed_at.to_rfc3339()));
    }
    pairs.push((
        "announced input digests allowed",
        if authority.input_digests.is_empty() {
            "none (any input)".to_owned()
        } else {
            authority.input_digests.join(", ")
        },
    ));
    pairs
}

fn history_erase(args: &HistoryEraseArgs) -> Result<HistoryEraseSuccessReport, FailureReport> {
    if !args.acknowledge_irreversible {
        return Err(FailureReport {
            ok: false,
            command: "history erase",
            diagnostics: vec![tool_diagnostic(
                diagnostic(
                    "history.erase.acknowledgement.required",
                    "acknowledgeIrreversible",
                    "history erasure is irreversible: no command restores erased revisions; pass --acknowledge-irreversible to proceed",
                ),
                DiagnosticArtifact::CommandArguments,
                SuggestedAction::CorrectCommandUsage,
            )],
        });
    }
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
        HistoryErasureLifecycleError::ActiveRegistry(error) => {
            return active_registry_failure("history erase", "history.erase", error);
        }
        HistoryErasureLifecycleError::Package(PackageError::ExpectedDigestMismatch(mismatch)) => {
            return package_pin_failure(
                "history erase",
                "history.erase.package.refused",
                "package",
                &mismatch,
            );
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
        HistoryErasureLifecycleError::ActiveRegistry(_) => unreachable!("handled before match"),
        HistoryErasureLifecycleError::Package(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
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
        HistoryErasureLifecycleError::Audit => (
            "history.erase.audit.unavailable",
            "audit",
            "the history erasure audit destination could not be opened; check the audit path and its directory permissions",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        HistoryErasureLifecycleError::Runtime => (
            "history.erase.runtime.unavailable",
            "runtime",
            "the history erasure runtime is unavailable",
            DiagnosticArtifact::HistoryErasure,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryErasureLifecycleError::Erasure(error) => match error {
            registry_breg::history_erasure::HistoryErasureError::InvalidInput
            | registry_breg::history_erasure::HistoryErasureError::TargetUnavailable => (
                "history.erase.target.refused",
                "requestFile",
                "the requested history erasure target was refused",
                DiagnosticArtifact::HistoryErasure,
                SuggestedAction::PrepareHistoryErasureRequest,
            ),
            registry_breg::history_erasure::HistoryErasureError::MigrationAuthority => (
                "history.erase.migration_authority.refused",
                "database",
                "history erasure requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::history_erasure::HistoryErasureError::CachedResponseUnreadable => (
                "history.erase.cached_response.invalid",
                "history",
                "history erasure found a cached response no JSON reader accepts",
                DiagnosticArtifact::HistoryErasure,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::history_erasure::HistoryErasureError::MigrationLockHeld => (
                "history.erase.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Nothing was erased. Retry the same erasure once it releases",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::RetryAfterMigrationLockReleases,
            ),
            registry_breg::history_erasure::HistoryErasureError::HistoryNotReady
            | registry_breg::history_erasure::HistoryErasureError::Unavailable => (
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
        HistoryRebaselineLifecycleError::ActiveRegistry(error) => {
            return active_registry_failure("history rebaseline", "history.rebaseline", error);
        }
        HistoryRebaselineLifecycleError::Package(PackageError::ExpectedDigestMismatch(
            mismatch,
        )) => {
            return package_pin_failure(
                "history rebaseline",
                "history.rebaseline.package.refused",
                "package",
                &mismatch,
            );
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
        HistoryRebaselineLifecycleError::ActiveRegistry(_) => unreachable!("handled before match"),
        HistoryRebaselineLifecycleError::Package(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
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
        HistoryRebaselineLifecycleError::Audit => (
            "history.rebaseline.audit.unavailable",
            "audit",
            "the history rebaseline audit destination could not be opened; check the audit path and its directory permissions",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        HistoryRebaselineLifecycleError::Runtime => (
            "history.rebaseline.runtime.unavailable",
            "runtime",
            "the history rebaseline runtime is unavailable",
            DiagnosticArtifact::HistoryRebaseline,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        HistoryRebaselineLifecycleError::Rebaseline(error) => match error {
            registry_breg::history_rebaseline::HistoryRebaselineError::InvalidInput => (
                "history.rebaseline.request.refused",
                "requestFile",
                "the history rebaseline request document was refused",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::PrepareHistoryRebaselineRequest,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::MigrationAuthority => (
                "history.rebaseline.migration_authority.refused",
                "database",
                "history rebaseline requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::CoverageComplete => (
                "history.rebaseline.coverage.complete",
                "history",
                "snapshot coverage is already complete, so there is nothing to rebaseline",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::PrepareHistoryRebaselineRequest,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::UnindexedRevisions => (
                "history.rebaseline.revisions.unindexed",
                "history",
                "history rebaseline requires every retained journal head to be indexed by a commit",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::ReviewRetainedHistory,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::LiveHistoryMismatch => (
                "history.rebaseline.live_rows.unverified",
                "history",
                "history rebaseline requires the retained journal head to reproduce every live row; \
                 the first record that disagrees is not named, so compare the live rows with their \
                 revisions to find it",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::ReviewRetainedHistory,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::MigrationLockHeld => (
                "history.rebaseline.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Nothing was changed. Retry the same rebaseline once it releases",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::RetryAfterMigrationLockReleases,
            ),
            registry_breg::history_rebaseline::HistoryRebaselineError::HistoryNotReady
            | registry_breg::history_rebaseline::HistoryRebaselineError::Unavailable => (
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

fn field_encryption_preflight(
    args: &FieldEncryptionPreflightArgs,
) -> Result<FieldEncryptionPreflightSuccessReport, FailureReport> {
    let outcome =
        field_encryption_lifecycle::run_preflight(FieldEncryptionPreflightLifecycleRequest {
            runtime_config: &args.runtime_config,
            package: &args.package,
        })
        .map_err(field_encryption_preflight_failure)?;
    // A collision the apply-side preflight would refuse is reported here as a
    // failed preflight, naming the authored record identifiers only.
    let collisions = outcome
        .report
        .steps
        .iter()
        .flat_map(|step| {
            step.fields
                .iter()
                .filter(|field| !field.duplicate_record_ids.is_empty())
                .map(|field| {
                    (
                        step.entity_id.clone(),
                        field.field_id.clone(),
                        field.duplicate_record_ids.clone(),
                    )
                })
        })
        .collect::<Vec<_>>();
    if !collisions.is_empty() {
        return Err(field_encryption_duplicate_failure(collisions));
    }
    Ok(FieldEncryptionPreflightSuccessReport {
        ok: true,
        command: "field-encryption preflight",
        outcome,
    })
}

fn field_encryption_duplicate_failure(
    collisions: Vec<(String, String, Vec<String>)>,
) -> FailureReport {
    let diagnostics = collisions
        .into_iter()
        .map(|(entity_id, field_id, record_ids)| {
            tool_diagnostic(
                diagnostic(
                    "field_encryption.preflight.duplicate_records",
                    "preflight",
                    &format!(
                        "entity {entity_id} field {field_id}: {} normalize onto one unique \
                         blind index, so the apply will refuse them; the records are {}",
                        record_ids.len(),
                        record_ids.join(", ")
                    ),
                ),
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::ReviewFieldEncryptionBackfill,
            )
        })
        .collect();
    FailureReport {
        ok: false,
        command: "field-encryption preflight",
        diagnostics,
    }
}

fn field_encryption_preflight_failure(
    error: FieldEncryptionPreflightLifecycleError,
) -> FailureReport {
    let error = match error {
        FieldEncryptionPreflightLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure(
                "field-encryption preflight",
                "field_encryption.preflight",
                error,
            );
        }
        FieldEncryptionPreflightLifecycleError::ActiveRegistry(error) => {
            return active_registry_failure(
                "field-encryption preflight",
                "field_encryption.preflight",
                error,
            );
        }
        FieldEncryptionPreflightLifecycleError::PredecessorPackage(
            PackageError::ExpectedDigestMismatch(mismatch),
        ) => {
            return package_pin_failure(
                "field-encryption preflight",
                "field_encryption.preflight.predecessor_package.refused",
                "package",
                &mismatch,
            );
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        FieldEncryptionPreflightLifecycleError::RuntimeConfigPath => (
            "field_encryption.preflight.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        FieldEncryptionPreflightLifecycleError::PackagePath => (
            "field_encryption.preflight.package.path_invalid",
            "package",
            "the successor package path must be absolute",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackagePath,
        ),
        FieldEncryptionPreflightLifecycleError::NoBackfillSteps => (
            "field_encryption.preflight.plan.no_backfill",
            "package",
            "the package plans no field-encryption backfill step to preflight",
            DiagnosticArtifact::FieldEncryption,
            SuggestedAction::ReviewFieldEncryptionBackfill,
        ),
        FieldEncryptionPreflightLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        FieldEncryptionPreflightLifecycleError::ActiveRegistry(_) => unreachable!("handled before match"),
        FieldEncryptionPreflightLifecycleError::PredecessorPackage(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "field_encryption.preflight.predecessor_package.refused",
                "package",
                "the active runtime package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        FieldEncryptionPreflightLifecycleError::TargetPackage(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "field_encryption.preflight.package.refused",
                "package",
                "the successor package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        FieldEncryptionPreflightLifecycleError::DatabaseConfiguration
        | FieldEncryptionPreflightLifecycleError::TimeoutConfiguration => (
            "field_encryption.preflight.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        FieldEncryptionPreflightLifecycleError::Runtime => (
            "field_encryption.preflight.runtime.unavailable",
            "runtime",
            "the field-encryption preflight runtime is unavailable",
            DiagnosticArtifact::FieldEncryption,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        FieldEncryptionPreflightLifecycleError::Preflight(error) => match error {
            registry_breg::field_encryption_backfill::FieldEncryptionBackfillPreflightError::InvalidInput => (
                "field_encryption.preflight.request.refused",
                "package",
                "the reviewed plan and the predecessor baseline do not agree on one field-encryption backfill",
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::ReviewFieldEncryptionBackfill,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionBackfillPreflightError::MigrationAuthority => (
                "field_encryption.preflight.migration_authority.refused",
                "database",
                "field-encryption preflight requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionBackfillPreflightError::Unavailable => (
                "field_encryption.preflight.unavailable",
                "database",
                "field-encryption preflight storage is unavailable",
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::VerifyMigrationAuthority,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "field-encryption preflight",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn field_encryption_erase_history(
    args: &FieldEncryptionEraseHistoryArgs,
) -> Result<FieldEncryptionEraseHistorySuccessReport, FailureReport> {
    let outcome = field_encryption_lifecycle::run_erase_history(
        FieldEncryptionEraseHistoryLifecycleRequest {
            runtime_config: &args.runtime_config,
            request_file: &args.request_file,
        },
    )
    .map_err(field_encryption_erase_history_failure)?;
    Ok(FieldEncryptionEraseHistorySuccessReport {
        ok: true,
        command: "field-encryption erase-history",
        outcome,
    })
}

fn field_encryption_erase_history_failure(
    error: FieldEncryptionEraseHistoryLifecycleError,
) -> FailureReport {
    let error = match error {
        FieldEncryptionEraseHistoryLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure(
                "field-encryption erase-history",
                "field_encryption.erase_history",
                error,
            );
        }
        FieldEncryptionEraseHistoryLifecycleError::ActiveRegistry(error) => {
            return active_registry_failure(
                "field-encryption erase-history",
                "field_encryption.erase_history",
                error,
            );
        }
        FieldEncryptionEraseHistoryLifecycleError::ActivePackage(
            PackageError::ExpectedDigestMismatch(mismatch),
        ) => {
            return package_pin_failure(
                "field-encryption erase-history",
                "field_encryption.erase_history.package.refused",
                "package",
                &mismatch,
            );
        }
        error => error,
    };
    let (code, path, message, artifact, action) = match error {
        FieldEncryptionEraseHistoryLifecycleError::RuntimeConfigPath => (
            "field_encryption.erase_history.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        FieldEncryptionEraseHistoryLifecycleError::RequestFile => (
            "field_encryption.erase_history.request_file.refused",
            "requestFile",
            "the erase-history request file must be absolute, owner-only, and bounded",
            DiagnosticArtifact::FieldEncryption,
            SuggestedAction::PrepareFieldEncryptionEraseRequest,
        ),
        FieldEncryptionEraseHistoryLifecycleError::RequestDocument => (
            "field_encryption.erase_history.request.refused",
            "requestFile",
            "the erase-history request document was refused",
            DiagnosticArtifact::FieldEncryption,
            SuggestedAction::PrepareFieldEncryptionEraseRequest,
        ),
        FieldEncryptionEraseHistoryLifecycleError::RuntimeConfig(_) => unreachable!("handled before match"),
        FieldEncryptionEraseHistoryLifecycleError::ActiveRegistry(_) => unreachable!("handled before match"),
        FieldEncryptionEraseHistoryLifecycleError::ActivePackage(error) => {
            let action = match error {
                PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
                PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
                PackageError::Binding => SuggestedAction::VerifyPackageBinding,
                _ => SuggestedAction::VerifyPackageIntegrity,
            };
            (
                "field_encryption.erase_history.package.refused",
                "package",
                "the active runtime package was refused",
                DiagnosticArtifact::VerifiedPackage,
                action,
            )
        }
        FieldEncryptionEraseHistoryLifecycleError::DatabaseConfiguration
        | FieldEncryptionEraseHistoryLifecycleError::TimeoutConfiguration => (
            "field_encryption.erase_history.database_configuration.refused",
            "database",
            "the migration database configuration was refused",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        FieldEncryptionEraseHistoryLifecycleError::Audit => (
            "field_encryption.erase_history.audit.unavailable",
            "audit",
            "the field-encryption erase-history audit destination could not be opened; check the audit path and its directory permissions",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        FieldEncryptionEraseHistoryLifecycleError::Runtime => (
            "field_encryption.erase_history.runtime.unavailable",
            "runtime",
            "the field-encryption erase-history runtime is unavailable",
            DiagnosticArtifact::FieldEncryption,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        FieldEncryptionEraseHistoryLifecycleError::Erase(error) => match error {
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::InvalidInput => (
                "field_encryption.erase_history.request.refused",
                "requestFile",
                "the erase-history request document was refused",
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::PrepareFieldEncryptionEraseRequest,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::MigrationAuthority => (
                "field_encryption.erase_history.migration_authority.refused",
                "database",
                "field-encryption history erasure requires the configured migration authority",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::NoPendingPlaintextHistory => (
                "field_encryption.erase_history.no_pending_plaintext",
                "history",
                "no retained plaintext history matches an erase-and-rebaseline flip, so there is nothing to erase",
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::ReviewFieldEncryptionBackfill,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::Erasure(
                error,
            ) => match error {
                registry_breg::history_erasure::HistoryErasureError::InvalidInput
                | registry_breg::history_erasure::HistoryErasureError::TargetUnavailable => (
                    "field_encryption.erase_history.target.refused",
                    "history",
                    "a pending per-record erasure was refused; the record that exceeded a bound \
                     is not named, and already-erased records stay erased, so the lifecycle can \
                     be re-run after the cause is addressed",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::ReviewRetainedHistory,
                ),
                registry_breg::history_erasure::HistoryErasureError::MigrationAuthority => (
                    "field_encryption.erase_history.migration_authority.refused",
                    "database",
                    "field-encryption history erasure requires the configured migration authority",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::VerifyMigrationAuthority,
                ),
                registry_breg::history_erasure::HistoryErasureError::CachedResponseUnreadable => (
                    "field_encryption.erase_history.cached_response.invalid",
                    "history",
                    "field-encryption history erasure found a cached response no JSON reader accepts",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::VerifyMigrationAuthority,
                ),
                registry_breg::history_erasure::HistoryErasureError::MigrationLockHeld => (
                    "field_encryption.erase_history.in_progress",
                    "database",
                    "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Records already erased stay erased. Retry the same erase-history once it releases",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::RetryAfterMigrationLockReleases,
                ),
                registry_breg::history_erasure::HistoryErasureError::HistoryNotReady
                | registry_breg::history_erasure::HistoryErasureError::Unavailable => (
                    "field_encryption.erase_history.unavailable",
                    "history",
                    "field-encryption history erasure storage is unavailable",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::VerifyMigrationAuthority,
                ),
            },
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::Rebaseline(
                error,
            ) => match error {
                registry_breg::history_rebaseline::HistoryRebaselineError::InvalidInput => (
                    "field_encryption.erase_history.request.refused",
                    "requestFile",
                    "the erase-history request document was refused",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::PrepareFieldEncryptionEraseRequest,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::MigrationAuthority => (
                    "field_encryption.erase_history.migration_authority.refused",
                    "database",
                    "the closing rebaseline requires the configured migration authority",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::VerifyMigrationAuthority,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::CoverageComplete => (
                    "field_encryption.erase_history.rebaseline.coverage_complete",
                    "history",
                    "snapshot coverage was already complete after the erasures, so no rebaseline ran",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::ReviewRetainedHistory,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::UnindexedRevisions => (
                    "field_encryption.erase_history.rebaseline.revisions_unindexed",
                    "history",
                    "the closing rebaseline requires every retained journal head to be indexed by a commit",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::ReviewRetainedHistory,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::LiveHistoryMismatch => (
                    "field_encryption.erase_history.rebaseline.live_rows_unverified",
                    "history",
                    "the closing rebaseline requires the retained journal head to reproduce every live \
                     row; the first record that disagrees is not named, so compare the live rows with \
                     their revisions to find it",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::ReviewRetainedHistory,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::MigrationLockHeld => (
                    "field_encryption.erase_history.in_progress",
                    "database",
                    "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Records already erased stay erased. Retry the same erase-history once it releases",
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::RetryAfterMigrationLockReleases,
                ),
                registry_breg::history_rebaseline::HistoryRebaselineError::HistoryNotReady
                | registry_breg::history_rebaseline::HistoryRebaselineError::Unavailable => (
                    "field_encryption.erase_history.rebaseline.unavailable",
                    "history",
                    "the closing rebaseline storage is unavailable",
                    DiagnosticArtifact::FieldEncryption,
                    SuggestedAction::VerifyMigrationAuthority,
                ),
            },
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::MigrationLockHeld => (
                "field_encryption.erase_history.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout, so an apply, an adoption, a migration reconcile, or other registry maintenance is in progress. Records already erased stay erased. Retry the same erase-history once it releases",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::RetryAfterMigrationLockReleases,
            ),
            registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError::Unavailable => (
                "field_encryption.erase_history.unavailable",
                "history",
                "field-encryption history erasure storage is unavailable",
                DiagnosticArtifact::FieldEncryption,
                SuggestedAction::VerifyMigrationAuthority,
            ),
        },
    };
    FailureReport {
        ok: false,
        command: "field-encryption erase-history",
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

fn webhook_discard(
    args: &WebhookDiscardArgs,
) -> Result<WebhookDiscardSuccessReport, FailureReport> {
    let outcome = webhook_lifecycle::discard(
        &args.runtime_config,
        &args.event_id,
        &args.delivery_id,
        args.expected_generation,
    )
    .map_err(|error| webhook_lifecycle_failure("webhook discard", error))?;
    Ok(WebhookDiscardSuccessReport {
        ok: true,
        command: "webhook discard",
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
        WebhookLifecycleError::PackagePinMismatch(mismatch) => {
            return package_pin_failure(command, "webhook.package.refused", "package", &mismatch)
        }
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
        input_digest: outcome.input_digest,
        item_count: outcome.item_count,
        chunk_count: outcome.chunk_count,
        maximum_items: outcome.maximum_items,
        maximum_bytes: outcome.maximum_bytes,
    })
}

fn data_import(args: &DataImportArgs) -> Result<DataImportSuccessReport, FailureReport> {
    let outcome = data_lifecycle::run_import(DataImportRequest {
        package: &args.package,
        breg_url: &args.breg_url,
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
        run_id: outcome.run_id,
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
        breg_url: &args.breg_url,
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

fn operation_arg(operation: registry_breg::data::DataImportOperation) -> DataOperationArg {
    match operation {
        registry_breg::data::DataImportOperation::Create => DataOperationArg::Create,
        registry_breg::data::DataImportOperation::Patch => DataOperationArg::Patch,
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
        DataLifecycleError::ImportRunBlocked(Some(BRegIngestionBlockedReason::ActivePackageChanged)) => (
            format!("{prefix}.ingestion_run.blocked"),
            "ingestionRun",
            "the ingestion run is blocked because the active package changed; the run stays inspectable, and a new import under the active package needs a fresh checkpoint path",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::ImportRunBlocked(Some(BRegIngestionBlockedReason::ImportAuthorityClosed)) => (
            format!("{prefix}.ingestion_run.import_authority_closed"),
            "ingestionRun",
            "the ingestion run is blocked because its import authority closed, expired, or has too little volume left for the next chunk; the committed chunks stay, and the remaining items need a new authority (bregctl import-authority list, then open) and a fresh checkpoint path",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::ImportRunBlocked(None) => (
            format!("{prefix}.ingestion_run.blocked"),
            "ingestionRun",
            "the ingestion run is blocked and refuses further chunks; read the run to see its blockedReason, and continue in a new import with a fresh checkpoint path",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::IngestionRunPrecondition { through_import: true } => (
            format!("{prefix}.ingestion_run.import_authority_required"),
            "ingestionRun",
            "the ingestion run was refused because no open import authority admits it: none is open for the entity, it names another profile, it expired, it has too little volume left, or it lists other input digests than the one the run announces; check bregctl import-authority list and open one that covers this input",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataBinding,
        ),
        DataLifecycleError::IngestionRunPrecondition { through_import: false } => (
            format!("{prefix}.ingestion_run.precondition_failed"),
            "ingestionRun",
            "the ingestion run was refused on a failed precondition",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataBinding,
        ),
        DataLifecycleError::ImportRunCancelled => (
            format!("{prefix}.ingestion_run.cancelled"),
            "ingestionRun",
            "the ingestion run was cancelled and refuses new chunks; start a new import with a fresh checkpoint path",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::Output => (
            format!("{prefix}.output.refused"),
            "output",
            "the data output was refused",
            DiagnosticArtifact::DataOperation,
            SuggestedAction::CorrectDataInput,
        ),
        DataLifecycleError::BRegUrl => (
            format!("{prefix}.breg_url.refused"),
            "bregUrl",
            "the Base Registry Engine URL was refused",
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
        DataLifecycleError::ExportPair(ExportPairState::CheckpointMissing) => (
            format!("{prefix}.checkpoint.missing"),
            "checkpoint",
            "the export output exists without the checkpoint that records it, which is what a run stopped before its first checkpoint leaves; remove the output file to export again, or name the checkpoint the output belongs to",
            DiagnosticArtifact::DataCheckpoint,
            SuggestedAction::VerifyDataCheckpoint,
        ),
        DataLifecycleError::ExportPair(ExportPairState::OutputMissing) => (
            format!("{prefix}.output.missing"),
            "output",
            "the export checkpoint exists without the output it records; remove the checkpoint file to export again, or name the output the checkpoint belongs to",
            DiagnosticArtifact::DataCheckpoint,
            SuggestedAction::VerifyDataCheckpoint,
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
    let (baseline_registry, baseline_revision, baseline_assurance) =
        match (&args.runtime_config, &args.package) {
            (Some(runtime_path), None) => {
                // The running package is the predecessor of the project being
                // diffed, so it is read the way test and package read a
                // baseline package: an earlier release's package is verified
                // against its sum file. Its changes are classified against the
                // packaged migration baseline, the schema the successor plan
                // runs over.
                let (predecessor, registry) = inspect_runtime_predecessor_rehearsal_baseline(
                    runtime_path,
                )
                .map_err(|error| match error {
                    RuntimePackageInspectionError::RuntimeConfigPath => diff_failure(
                        "diff.runtime_config.path_invalid",
                        "runtimeConfig",
                        "the runtime configuration path must be absolute",
                    ),
                    RuntimePackageInspectionError::RuntimeConfig(error) => {
                        runtime_config_diff_failure(error)
                    }
                    RuntimePackageInspectionError::Package(error) => package_diff_failure(error),
                    RuntimePackageInspectionError::SharedPackage(message) => {
                        diff_failure("diff.package.integrity_refused", "package", &message)
                    }
                })?;
                (
                    registry.with_migration_baseline_schema(predecessor.migration_baseline()),
                    predecessor.package_digest().to_owned(),
                    BaselineAssurance::RuntimeBound,
                )
            }
            (None, Some(package_root)) => {
                let inspected =
                    inspect_package_integrity(package_root).map_err(package_diff_failure)?;
                (
                    inspected.registry().clone(),
                    inspected.package_digest().to_owned(),
                    BaselineAssurance::IntegrityOnly,
                )
            }
            _ => unreachable!("clap enforces exactly one diff baseline selector"),
        };
    let compiled_diff = classify_registry_diff(&baseline_registry, &candidate, &baseline_revision);
    let mut compiler_findings = candidate.findings().to_vec();
    compiler_findings.extend(unsupported_diff_findings(&compiled_diff));
    compiler_findings.extend(removed_value_findings(&compiled_diff));
    compiler_findings.sort();
    compiler_findings.dedup();
    let findings = compiler_findings
        .into_iter()
        .map(|diagnostic| {
            let (artifact, action) = if diagnostic.code == "diff.classification.unsupported"
                || diagnostic.code == REMOVED_VALUES_RETAINED_CODE
            {
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
    let outcome = package_lifecycle::run(prepared, receipt, &args.output, args.revision.as_deref())
        .map_err(package_lifecycle_failure)?;
    Ok(PackageSuccessReport {
        ok: true,
        command: "package",
        profile: ProfileArg::Production,
        package_digest: outcome.package_digest,
        registry_revision: outcome.registry_revision,
        package_files: outcome.package_files,
        revision: outcome.revision,
    })
}

fn test(args: &TestArgs) -> Result<SchemaTestSuccessReport, FailureReport> {
    let (Some(credentials), Some(output)) = (&args.credentials, &args.output) else {
        unreachable!("clap requires --credentials and --output unless --fingerprint-only is set")
    };
    let output = test_lifecycle::preflight_output(output).map_err(test_lifecycle_failure)?;
    let candidate = capture_candidate(&args.candidate, "test", true)?;
    let outcome = test_lifecycle::run(TestLifecycleRequest {
        candidate,
        runtime_config: &args.runtime_config,
        credentials,
        output,
    })
    .map_err(test_lifecycle_failure)?;
    Ok(SchemaTestSuccessReport {
        ok: true,
        command: "test",
        profile: ProfileArg::Production,
        registry_revision: outcome.registry_revision,
        schema_fingerprint: outcome.schema_fingerprint,
        successful_journey_ids: outcome.successful_journey_ids,
        receipt: ArtifactReport {
            path: test_lifecycle::receipt_artifact_path().to_owned(),
            media_type: "application/json".to_owned(),
            sha256: outcome.receipt_sha256,
            byte_length: outcome.receipt_bytes,
        },
        diagnostics: outcome
            .baseline_fingerprint_drift
            .iter()
            .map(baseline_fingerprint_drift_finding)
            .collect(),
    })
}

/// Measure the fresh-install schema fingerprint a reviewed migration declares
/// as its target, without the fixture run or receipt of a full schema test.
fn measure_schema_fingerprint(args: &TestArgs) -> Result<SchemaFingerprintReport, FailureReport> {
    let candidate = capture_candidate(&args.candidate, "test", false)?;
    let measurement =
        test_lifecycle::measure(candidate, &args.runtime_config).map_err(test_lifecycle_failure)?;
    Ok(SchemaFingerprintReport {
        ok: true,
        command: "test",
        profile: ProfileArg::Production,
        registry_revision: measurement.registry_revision,
        schema_fingerprint: measurement.schema_fingerprint,
    })
}

/// The advisory finding for a predecessor schema that this compiler installs
/// differently from the fingerprint its package binds.
fn baseline_fingerprint_drift_finding(drift: &BaselineFingerprintDrift) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Finding,
        code: "migration.rehearsal.baseline_fingerprint_drift".to_owned(),
        path: "baselinePackage".to_owned(),
        message: format!(
            "the predecessor schema this bregctl installs measures {}, but its package binds {}; \
             an earlier bregctl release built it, or this compiler installs it differently. The successor \
             migration was rehearsed over this bregctl's installation of the predecessor and reaches the \
             candidate fingerprint; apply checks the live database before it migrates",
            drift.measured, drift.signed
        ),
    }
}

/// Compile the verified predecessor so `test` can rehearse the successor
/// migration over its schema. The predecessor was verified a moment earlier;
/// this second read is bound to the same package digest.
fn capture_rehearsal_baseline(
    command: &'static str,
    baseline_package: &std::path::Path,
    package_digest: &str,
) -> Result<RehearsalBaseline, FailureReport> {
    let unavailable = || {
        candidate_failure(
            command,
            "migration.rehearsal.baseline_unavailable",
            "baselinePackage",
            "the current compiler cannot rebuild the verified predecessor registry from its packaged sources, so the successor migration cannot be rehearsed; run test with a bregctl release that compiles the predecessor sources",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackageIntegrity,
        )
    };
    let (predecessor, registry) =
        inspect_baseline_rehearsal(baseline_package).map_err(|_| unavailable())?;
    if predecessor.package_digest() != package_digest {
        return Err(unavailable());
    }
    Ok(RehearsalBaseline {
        registry,
        schema_fingerprint: predecessor.schema_fingerprint().to_owned(),
    })
}

fn prepare_candidate(
    args: &PackageCandidateArgs,
    schema_fingerprint: String,
    command: &'static str,
) -> Result<PreparedPackage, FailureReport> {
    capture_candidate(args, command, false)?
        .prepare(schema_fingerprint)
        .map_err(|error| candidate_package_error(command, error))
}

fn capture_candidate(
    args: &PackageCandidateArgs,
    command: &'static str,
    rehearse_successor: bool,
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
    let mut rehearsal_baseline = None;
    let mut reviewed_changes = String::new();
    let (from_package_digest, migration_plan) = match args.baseline_package.as_deref() {
        Some(baseline_package) => {
            let baseline = inspect_baseline_package(baseline_package)
                .map_err(|error| baseline_package_failure(command, error))?;
            if baseline.package_id() != compiled.registry_id() {
                return Err(candidate_failure(
                    command,
                    "package.baseline.identity",
                    "baselinePackage",
                    "the baseline package belongs to another registry; name this registry's chain tip package directory with --baseline-package",
                    DiagnosticArtifact::VerifiedPackage,
                    SuggestedAction::CorrectPackageBuild,
                ));
            }
            if rehearse_successor {
                rehearsal_baseline = Some(capture_rehearsal_baseline(
                    command,
                    baseline_package,
                    baseline.package_digest(),
                )?);
            }
            let changes = registry_breg::package::compiled_registry_change_set_from_baseline(
                baseline.migration_baseline(),
                &compiled,
                baseline.package_digest(),
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
                if registry_breg::package::change_set_to_applicable_migration_plan(&changes)
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
            (Some(baseline.package_digest().to_owned()), plan)
        }
        None => (None, PackageMigrationPlanInput::InitialCompiledDdl),
    };
    let candidate = CapturedPackageCandidate {
        compiled,
        from_package_digest,
        compiler_source_revision,
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
        rehearsal_baseline,
    };
    if args.reviewed_migrations.is_some() {
        candidate.prevalidate().map_err(|error| {
            // The generic code is the fallback for a structural precondition
            // (predecessor digest, baseline binding) that never reaches
            // `ReviewedMigrationError`; a reviewed plan refusal names its kind.
            let code = match error {
                PackageError::ReviewedMigration(ReviewedMigrationError::Descriptor) => {
                    "migration.review.descriptor_refused"
                }
                PackageError::ReviewedMigration(ReviewedMigrationError::Coverage) => {
                    "migration.review.coverage_refused"
                }
                PackageError::ReviewedMigration(ReviewedMigrationError::Sql) => {
                    "migration.review.sql_refused"
                }
                PackageError::ReviewedMigration(ReviewedMigrationError::Evidence) => {
                    "migration.review.evidence_refused"
                }
                PackageError::ReviewedMigration(ReviewedMigrationError::Closure) => {
                    "migration.review.closure_refused"
                }
                _ => "migration.review.refused",
            };
            candidate_failure(
                command,
                code,
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
        acknowledge_retired_audit_discard: args.acknowledge_retired_audit_discard,
        operator_reference: args.operator_reference.as_deref(),
        expected_digest: args.expected_digest.as_deref(),
    })
    .map_err(apply_lifecycle_failure)?;
    Ok(ApplySuccessReport {
        ok: true,
        command: "apply",
        activation: match outcome.activation {
            ApplyLifecycleActivation::Initial => ApplyActivation::Initial,
            ApplyLifecycleActivation::Successor => ApplyActivation::Successor,
            ApplyLifecycleActivation::RoleChange => ApplyActivation::RoleChange,
        },
        package_digest: outcome.package_digest,
        schema_fingerprint: outcome.schema_fingerprint,
        activation_id: outcome.activation_id,
    })
}

fn plan(args: &PlanArgs) -> Result<PlanSuccessReport, FailureReport> {
    let outcome = apply_lifecycle::plan(PlanLifecycleRequest {
        runtime_config: &args.runtime_config,
        package: &args.package,
        backups: &args.backups,
        expected_digest: args.expected_digest.as_deref(),
    })
    .map_err(|error| lifecycle_failure("plan", error))?;
    Ok(PlanSuccessReport {
        ok: true,
        command: "plan",
        pending: outcome.plan.activation.is_pending(),
        activation: match outcome.plan.activation {
            registry_breg::migration::PlannedActivation::Initial => PlanActivation::Initial,
            registry_breg::migration::PlannedActivation::Successor => PlanActivation::Successor,
            registry_breg::migration::PlannedActivation::RoleChange => PlanActivation::RoleChange,
            registry_breg::migration::PlannedActivation::AlreadyActive => PlanActivation::None,
        },
        package_digest: outcome.package_digest,
        registry_revision: outcome.registry_revision,
        active_package_digest: outcome.active_package_digest,
        role_mode: outcome.plan.role_mode,
        resumes_activation_id: outcome.plan.resumes_activation_id,
        required_backups: outcome.plan.required_backups,
        checks: outcome.plan.checks,
        migration: outcome.migration,
    })
}

fn status(args: &StatusArgs) -> Result<StatusSuccessReport, FailureReport> {
    let status = apply_lifecycle::status(&args.runtime_config)
        .map_err(status_lifecycle_failure)?
        .ok_or_else(|| status_lifecycle_failure(ApplyLifecycleError::Uninitialized))?;
    let active = status.active_entry().cloned();
    Ok(StatusSuccessReport {
        ok: true,
        command: "status",
        package_id: status.identity.package_id,
        database_id: status.identity.database_id,
        active_package_digest: status.identity.package_digest,
        activation_id: status.identity.activation_id,
        registry_revision: active.as_ref().map(|entry| entry.registry_revision.clone()),
        role_mode: active.map(|entry| entry.role_mode),
        schema_fingerprint: status.identity.schema_fingerprint,
        maintenance_status: status.maintenance_status,
        maintenance_target_package_digest: status.maintenance_target_package_digest,
        ledger: status
            .ledger
            .into_iter()
            .map(|entry| StatusLedgerEntry {
                activation_id: entry.activation_id,
                apply_order: entry.apply_order,
                package_digest: entry.package_digest,
                predecessor_package_digest: entry.predecessor_package_digest,
                registry_revision: entry.registry_revision,
                plan_kind: entry.plan_kind,
                migration_kind: entry.migration_kind,
                outcome: entry.outcome,
                role_mode: entry.role_mode,
                started_at: entry.started_at,
                completed_at: entry.completed_at,
                applied_at: entry.applied_at,
            })
            .collect(),
    })
}

fn status_lifecycle_failure(error: ApplyLifecycleError) -> FailureReport {
    let (code, path, message, artifact, action) = match error {
        ApplyLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure("status", "status", error);
        }
        ApplyLifecycleError::RuntimeConfigPath => (
            "status.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::DatabaseConfiguration | ApplyLifecycleError::TimeoutConfiguration => (
            "status.database_configuration.refused",
            "database",
            "the migration database configuration was refused: correct database.migrationUrlRef, its secret, and the migration timeouts in the runtime configuration, then run `bregctl status` again",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::Uninitialized => (
            "status.database.uninitialized",
            "database",
            "the database records no activated registry: run `bregctl plan --package DIR` to check the first package, then `bregctl apply --initial --package DIR` to activate it",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::Apply(registry_breg::migration::MigrationError::UnrecognizedDatabase) => (
            "status.database.unrecognized",
            "database",
            "the database holds registry state this release does not recognise, such as state written by a release older than its immediate predecessor: a release reads only the state its predecessor wrote, so upgrade one release at a time",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::Apply(registry_breg::migration::MigrationError::DatabaseUnavailable) => (
            "status.database.unavailable",
            "database",
            "the migration database could not be reached: check database.migrationUrlRef and that the database accepts the migration role, then run `bregctl status` again",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::Runtime => (
            "status.runtime.unavailable",
            "runtime",
            "the status runtime is unavailable",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        _ => (
            "status.database.refused",
            "database.roles.migration",
            "the database refused the activation state read: the connection must use database.roles.migration, which must own the registry schemas and hold no superuser, CREATEDB, CREATEROLE, or BYPASSRLS authority; correct the role, then run `bregctl status` again",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
    };
    FailureReport {
        ok: false,
        command: "status",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, message),
            artifact,
            action,
        )],
    }
}

fn package_lifecycle_failure(error: PackageLifecycleError) -> FailureReport {
    match error {
        PackageLifecycleError::Package(error) => {
            let (code, action) = match error {
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
            DiagnosticArtifact::PackageBuild,
            SuggestedAction::ChooseSafeOutputDirectory,
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

fn schema_test_runtime_setup_failure(
    error: registry_breg::fixtures::SchemaTestRuntimeSetupError,
) -> FailureReport {
    use registry_breg::event_destination::EventDestinationActivationError;
    use registry_breg::fixtures::SchemaTestRuntimeSetupError;

    let (code, path, recovery) = match &error {
        SchemaTestRuntimeSetupError::Authentication => (
            "test.authentication.setup_failed",
            "authentication",
            "check the authentication configuration, OIDC key source availability, and referenced secrets before retrying",
        ),
        SchemaTestRuntimeSetupError::Audit => (
            "test.audit.setup_failed",
            "audit",
            "check the audit configuration and referenced key material before retrying",
        ),
        SchemaTestRuntimeSetupError::Cursor => (
            "test.cursor.setup_failed",
            "cursor",
            "check the cursor configuration and referenced key material before retrying",
        ),
        SchemaTestRuntimeSetupError::EventDestinations(
            EventDestinationActivationError::InventoryMismatch,
        ) => (
            "test.event_destinations.inventory_mismatch",
            "eventDestinations",
            "configure exactly the logical destination bindings required by the candidate event deliveries before retrying",
        ),
        SchemaTestRuntimeSetupError::EventDestinations(_) => (
            "test.event_destinations.activation_failed",
            "eventDestinations",
            "check the destination bindings, delivery ceilings, and referenced secret, signing, and TLS material before retrying",
        ),
        SchemaTestRuntimeSetupError::Evidence => (
            "test.evidence_providers.activation_failed",
            "evidenceProviders",
            "check the Evidence provider bindings and referenced credentials against the candidate before retrying",
        ),
        SchemaTestRuntimeSetupError::ReviewAuthorities => (
            "test.review_authorities.activation_failed",
            "reviewAuthorities",
            "bind every review authority the candidate's change requests name, and check the referenced credentials, before retrying",
        ),
        SchemaTestRuntimeSetupError::WasmExecution => (
            "test.wasm_execution.setup_failed",
            "wasmExecution",
            "check the WASM execution budgets and backend support before retrying",
        ),
    };
    FailureReport {
        ok: false,
        command: "test",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, &format!("{error}; {recovery}")),
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        )],
    }
}

fn test_lifecycle_failure(error: TestLifecycleError) -> FailureReport {
    let error = match error {
        TestLifecycleError::RuntimeSetup(error) => return schema_test_runtime_setup_failure(error),
        TestLifecycleError::FieldPatternSyntax {
            entity_id,
            field_id,
        } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic("field.pattern.syntax_invalid", &format!("entities[{entity_id}].fields[{field_id}].pattern"),
                        "the persisted field pattern has invalid PostgreSQL ARE syntax; correct the expression and rerun schema-test"),
                    DiagnosticArtifact::SchemaTestCandidate,
                    SuggestedAction::CorrectSchemaTestCandidate,
                )],
            };
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
        TestLifecycleError::Rehearsal(error) => return migration_rehearsal_failure(*error),
        // Both values are schema digests, not secrets: naming them lets the
        // author tell a stale review from a candidate that changed since.
        TestLifecycleError::ReviewFingerprint { declared, measured } => {
            return FailureReport {
                ok: false,
                command: "test",
                diagnostics: vec![tool_diagnostic(
                    diagnostic(
                        "migration.review.fingerprint_mismatch",
                        "reviewedMigrations",
                        &format!(
                            "the reviewed target fingerprint {declared} does not match the schema measured on the disposable database, {measured}; measure the exact candidate with test --fingerprint-only, then correct the review evidence before retrying"
                        ),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::CorrectPackageBuild,
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
        TestLifecycleError::RuntimeSetup(_) => unreachable!("handled before match"),
        TestLifecycleError::JourneySyntax { .. } => unreachable!("handled before match"),
        TestLifecycleError::Journeys { .. } => unreachable!("handled before match"),
        TestLifecycleError::Credentials { .. } => unreachable!("handled before match"),
        TestLifecycleError::JourneyStep { .. } => unreachable!("handled before match"),
        TestLifecycleError::Rehearsal(_) => unreachable!("handled before match"),
        TestLifecycleError::Candidate => (
            "test.candidate.refused",
            "candidate",
            "the schema-test package candidate was refused",
            DiagnosticArtifact::SchemaTestCandidate,
            SuggestedAction::CorrectSchemaTestCandidate,
        ),
        TestLifecycleError::ReviewFingerprint { .. } => unreachable!("handled before match"),
        TestLifecycleError::FieldPatternSyntax { .. } => unreachable!("handled before match"),
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

/// Report a refused successor-migration rehearsal. Every message is built from
/// authored identifiers and PostgreSQL's value-free error fields, never from a
/// server message or detail.
fn migration_rehearsal_failure(error: MigrationRehearsalError) -> FailureReport {
    let (code, path, action) = match &error {
        MigrationRehearsalError::Database => (
            "test.database.unavailable",
            "database".to_owned(),
            SuggestedAction::RecreateDisposableDatabase,
        ),
        MigrationRehearsalError::NotSuccessor | MigrationRehearsalError::ReviewedPlan => (
            "test.candidate.refused",
            "candidate".to_owned(),
            SuggestedAction::CorrectPackageBuild,
        ),
        MigrationRehearsalError::BaselineNotReproducible => (
            "migration.rehearsal.baseline_not_reproducible",
            "baselinePackage".to_owned(),
            SuggestedAction::VerifyPackageIntegrity,
        ),
        MigrationRehearsalError::CompilerStatement { statement_id, .. } => (
            "migration.rehearsal.compiler_statement_failed",
            format!("migrationPlan.statements[{statement_id}]"),
            SuggestedAction::CorrectPackageBuild,
        ),
        MigrationRehearsalError::Assertion {
            migration_id,
            phase,
            assertion_id,
            ..
        }
        | MigrationRehearsalError::AssertionShape {
            migration_id,
            phase,
            assertion_id,
        } => (
            "migration.rehearsal.assertion_failed",
            format!("reviewedMigrations[{migration_id}].{phase}Assertions[{assertion_id}]"),
            SuggestedAction::CorrectPackageBuild,
        ),
        MigrationRehearsalError::Step {
            migration_id,
            step_id,
            ..
        } => (
            "migration.rehearsal.step_failed",
            format!("reviewedMigrations[{migration_id}].steps[{step_id}]"),
            SuggestedAction::CorrectPackageBuild,
        ),
        MigrationRehearsalError::HistoryStep {
            migration_id,
            step_id,
            ..
        } => (
            "migration.rehearsal.history_step_refused",
            format!("reviewedMigrations[{migration_id}].steps[{step_id}]"),
            SuggestedAction::CorrectPackageBuild,
        ),
        MigrationRehearsalError::FinalSchemaMismatch => (
            "migration.rehearsal.schema_mismatch",
            "reviewedMigrations".to_owned(),
            SuggestedAction::CorrectPackageBuild,
        ),
    };
    let artifact = if matches!(error, MigrationRehearsalError::Database) {
        DiagnosticArtifact::SchemaTestDatabase
    } else {
        DiagnosticArtifact::DatabaseMigration
    };
    let message = format!(
        "the successor migration was rehearsed over an empty copy of the verified predecessor schema and refused, so apply would refuse it too: {error}"
    );
    FailureReport {
        ok: false,
        command: "test",
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, &path, &message),
            artifact,
            action,
        )],
    }
}

fn apply_lifecycle_failure(error: ApplyLifecycleError) -> FailureReport {
    lifecycle_failure("apply", error)
}

/// Maps an apply lifecycle refusal for `apply` or `plan`: a plan runs apply's
/// checks, so it refuses with apply's codes and names the same next command.
fn lifecycle_failure(command: &'static str, error: ApplyLifecycleError) -> FailureReport {
    let error = match error {
        ApplyLifecycleError::RuntimeConfig(error) => {
            return runtime_config_failure(command, "apply", error);
        }
        ApplyLifecycleError::CurrentPackage(PackageError::ExpectedDigestMismatch(mismatch)) => {
            return package_pin_failure(
                command,
                "apply.package.refused",
                "package.root",
                &mismatch,
            );
        }
        ApplyLifecycleError::PackageDigestMismatch { expected, found } => {
            return FailureReport {
                ok: false,
                command,
                diagnostics: vec![tool_diagnostic(
                    diagnostic(
                        "apply.package.digest_mismatch",
                        "package",
                        &format!(
                            "--expected-digest is {expected} but the package at --package is {found}; nothing was changed. Run `bregctl plan` on the intended package and pass the digest it reports"
                        ),
                    ),
                    DiagnosticArtifact::VerifiedPackage,
                    SuggestedAction::RerunPlanOnIntendedPackage,
                )],
            };
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
        ApplyLifecycleError::PackageDigestMismatch { .. } => unreachable!("handled before match"),
        ApplyLifecycleError::TargetPackagePath => (
            "apply.package.path_invalid",
            "package",
            "the target package path must be absolute",
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackagePath,
        ),
        ApplyLifecycleError::TargetPackage(error) => (
            "apply.package.refused",
            "package",
            package_refusal_message(&error, "the activation package was refused"),
            DiagnosticArtifact::VerifiedPackage,
            package_refusal_action(&error),
        ),
        // The configured active package is refused apart from the target, so
        // the operator reads which of the two directories to fix.
        ApplyLifecycleError::CurrentPackage(error) => (
            "apply.package.refused",
            "package.root",
            match error {
                PackageError::LegacyFormat => {
                    "the active package at package.root uses the retired package/v1 manifest format: rebuild the deployed project with this release's `bregctl package`, point package.root at the rebuilt package, and run the command again"
                }
                _ => {
                    "the active package at package.root was refused"
                }
            },
            DiagnosticArtifact::VerifiedPackage,
            package_refusal_action(&error),
        ),
        ApplyLifecycleError::Uninitialized => (
            "apply.database.uninitialized",
            "database",
            "the database records no activated registry for this package; run `bregctl apply --initial` to activate the first package. Nothing was changed",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::EventDestinations => (
            "apply.event_destinations.refused",
            "eventDestinations",
            "the event destination bindings were refused",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::FieldEncryptionConfiguration => (
            "apply.field_encryption.configuration_refused",
            "fieldEncryption.provider",
            "the field-encryption key provider is required and must resolve for this package",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::FieldEncryptionCustody => (
            "apply.field_encryption.custody_refused",
            "fieldEncryption.provider",
            "a local-file field-encryption key is allowed only for local database initialization",
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
        ApplyLifecycleError::Audit => (
            "apply.audit.unavailable",
            "audit",
            "the activation audit destination could not be opened; check the audit path and its directory permissions",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ApplyLifecycleError::Runtime => (
            "apply.runtime.unavailable",
            "runtime",
            "the package apply runtime is unavailable",
            DiagnosticArtifact::PackageActivation,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ApplyLifecycleError::Apply(error) => match error {
            registry_breg::migration::MigrationError::FieldPatternSyntax {
                entity_id,
                field_id,
            } => {
                return source_failure(
                    command,
                    diagnostic(
                        "field.pattern.syntax_invalid",
                        &format!("entities[{entity_id}].fields[{field_id}].pattern"),
                        "PostgreSQL rejected the native pattern syntax. The exact target remains pinned in maintenance; restore the pre-activation backup before correcting the PostgreSQL ARE syntax, schema-testing, and packaging the correction. Do not retry changed package bytes as the pinned target.",
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReconcileFailedMigration,
                );
            }
            registry_breg::migration::MigrationError::FieldPatternExistingRows {
                entity_id,
                field_id,
            } => {
                return source_failure(
                    command,
                    diagnostic(
                        "field.pattern.existing_rows_invalid",
                        &format!("entities[{entity_id}].fields[{field_id}].pattern"),
                        "Existing stored values do not satisfy the native pattern. The exact target remains pinned in maintenance; repair the violating values through operator recovery and retry the exact pinned target.",
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReconcileFailedMigration,
                );
            }
            registry_breg::migration::MigrationError::FieldEncryptionLookupCollision {
                entity_id,
                record_ids,
            } => {
                return source_failure(
                    command,
                    diagnostic(
                        "field_encryption.lookup.collision",
                        &format!("entities[{entity_id}]"),
                        &format!(
                            "Existing records normalize onto one unique blind index, so the \
                             field-encryption backfill refused before sealing anything. The exact \
                             target remains pinned in maintenance; repair the colliding values of \
                             the {} named records through operator recovery and retry the exact \
                             pinned target: {}",
                            record_ids.len(),
                            record_ids.join(", ")
                        ),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReviewFieldEncryptionBackfill,
                );
            }
            registry_breg::migration::MigrationError::FieldEncryptionRetainedRequestSnapshots {
                entity_id,
                field_id,
            } => {
                return source_failure(
                    command,
                    diagnostic(
                        "field_encryption.history.retained_request_snapshot",
                        &format!("entities[{entity_id}].fields[{field_id}].encryption"),
                        "Retained change-request snapshots still contain plaintext for this field. Choose erase-and-rebaseline history handling, or remove the retained snapshots through the documented operator workflow before retrying the exact pinned target.",
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReviewFieldEncryptionBackfill,
                );
            }
            registry_breg::migration::MigrationError::ActivationAuditIncomplete => (
                "apply.audit.incomplete",
                "audit",
                "the package was activated, but the audit destination refused a record the activation owed, so the audit trail is incomplete: do not apply again; check the audit path and its directory permissions, and run `bregctl status` to see the active package",
                DiagnosticArtifact::RuntimeConfiguration,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::ActivationAuditUnavailable => (
                "apply.audit.unavailable",
                "audit",
                "the audit destination refused the activation's request entry, so the activation did not start: check the audit path and its directory permissions, then run the same `bregctl apply` again. Nothing was changed",
                DiagnosticArtifact::RuntimeConfiguration,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::OperatorReference => (
                "apply.operator_reference.refused",
                "operatorReference",
                "--operator-reference must be 1 to 512 bytes without control characters, and the runtime audit profile must be keyed to record its hash: correct the reference or the audit profile and apply again. Nothing was changed",
                DiagnosticArtifact::RuntimeConfiguration,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::ActivePackageMismatch => (
                "apply.package.active_mismatch",
                "package.root",
                "package.root names a package the database does not record as its active, ready package: set package.root to the active package directory, which `bregctl status` reports, and apply again; if the database has never been activated, apply it with --initial; if the database is pinned in maintenance, assess it with migration reconcile. Nothing was changed",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::AlreadyActive => {
                return FailureReport {
                    ok: false,
                    command,
                    diagnostics: vec![tool_diagnostic(
                        diagnostic(
                            "apply.package.already_active",
                            "package",
                            "the database already runs this package with the configured database roles, so there is nothing to apply; run `bregctl status` to see the active package. Nothing was changed",
                        ),
                        DiagnosticArtifact::PackageActivation,
                        SuggestedAction::CorrectPackageBuild,
                    )],
                };
            }
            registry_breg::migration::MigrationError::DatabaseMismatch => (
                "apply.database.identity_mismatch",
                "identity.databaseId",
                "the database records another database id than identity.databaseId: point database.migrationUrlRef at the database identity.databaseId names, or correct identity.databaseId. Nothing was changed",
                DiagnosticArtifact::RuntimeConfiguration,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::EmptyPlan => (
                "apply.package.empty_plan",
                "package",
                "the successor package has nothing to apply: its migration plan has no schema statement and no reviewed migration, and it is not an access or disclosure change alone; keep the active package until the registry model changes, then build the successor from that change. Nothing was changed",
                DiagnosticArtifact::VerifiedPackage,
                SuggestedAction::CorrectPackageBuild,
            ),
            registry_breg::migration::MigrationError::PackageBinding => (
                "apply.package.refused",
                "package",
                "the target package does not follow the active package: it must be this registry's package and its migrationPlan.fromPackageDigest must name the active package digest; build the successor with `bregctl package --baseline-package <active package directory>`. Packages apply forward only: to undo a change, build and apply a successor that reverts it, or restore the pre-activation backup: https://docs.registrystack.org/operate/breg-changes/#roll-back-by-rolling-forward. Nothing was changed",
                DiagnosticArtifact::VerifiedPackage,
                SuggestedAction::VerifyPackageBinding,
            ),
            registry_breg::migration::MigrationError::BackupEvidence => (
                "apply.backup_evidence.refused",
                "backup",
                "the destructive backup evidence was refused",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::CorrectPackageBuild,
            ),
            registry_breg::migration::MigrationError::HistoryCoverage => (
                "apply.history.coverage_incomplete",
                "history",
                "retained history coverage does not admit a successor package, so maintenance state was not changed: finish a pending field-encryption erase-history run, or run history rebaseline after a history erasure, then apply the same package again; see https://docs.registrystack.org/operate/breg-retention/#restore-snapshot-coverage-after-an-erasure",
                DiagnosticArtifact::HistoryRebaseline,
                SuggestedAction::PrepareHistoryRebaselineRequest,
            ),
            registry_breg::migration::MigrationError::DatabaseUnavailable => (
                "apply.database.unavailable",
                "database",
                "the migration database could not be reached before maintenance began. Nothing was changed. Retry the same apply once the database is reachable and accepts the migration role",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::VerifyMigrationAuthority,
            ),
            registry_breg::migration::MigrationError::MigrationLockHeld => (
                "apply.database.in_progress",
                "database",
                "another session held the exclusive migration lock past the lock timeout before maintenance began, so an apply, an adoption, or a migration reconcile is in progress. Nothing was changed. Retry the same apply once it releases",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::RetryAfterMigrationLockReleases,
            ),
            registry_breg::migration::MigrationError::StatementFailed(failure) => {
                return source_failure(
                    command,
                    diagnostic(
                        "apply.migration.statement_failed",
                        "database",
                        &format!(
                            "PostgreSQL refused an apply statement with {failure}. The exact target remains pinned in maintenance: fix the cause the SQLSTATE and the named objects point at and retry the same target, or assess the pinned target with migration reconcile"
                        ),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::ReconcileFailedMigration,
                );
            }
            registry_breg::migration::MigrationError::ApplyFailed => (
                "apply.migration.failed",
                "database",
                "the Registry package apply failed and requires exact-target reconciliation",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::ReconcileFailedMigration,
            ),
            registry_breg::migration::MigrationError::ActiveRequestProposals => (
                "apply.request_proposals.active",
                "changeRequest",
                "active request proposals require explicit rebase or cancellation before activating changed request contracts",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::ResolveActiveRequestProposals,
            ),
            registry_breg::migration::MigrationError::UnrecognizedDatabase => (
                "apply.database.unrecognized",
                "database",
                "the database holds registry state this release does not recognise, such as state written by a release older than its immediate predecessor: a release reads only the state its predecessor wrote, so upgrade one release at a time. Nothing was changed",
                DiagnosticArtifact::PackageActivation,
                SuggestedAction::CorrectRuntimeConfiguration,
            ),
            registry_breg::migration::MigrationError::RuntimeWriteAuthority(finding) => {
                return source_failure(
                    command,
                    diagnostic(
                        "apply.runtime_role.can_write",
                        "database.roles.runtime",
                        &format!("{finding}. Nothing was changed"),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::VerifyMigrationAuthority,
                );
            }
            registry_breg::migration::MigrationError::ResumeRolesDiffer { .. } => {
                return source_failure(
                    "apply",
                    diagnostic(
                        "apply.resume.roles_differ",
                        "database.roles",
                        &format!("{error}. Nothing was changed"),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::CorrectRuntimeConfiguration,
                );
            }
            registry_breg::migration::MigrationError::SuccessorRolesDiffer { .. } => {
                return source_failure(
                    "apply",
                    diagnostic(
                        "apply.successor.roles_differ",
                        "database.roles",
                        &format!("{error}. Nothing was changed"),
                    ),
                    DiagnosticArtifact::DatabaseMigration,
                    SuggestedAction::CorrectRuntimeConfiguration,
                );
            }
            registry_breg::migration::MigrationError::RetiredAuditRowsPresent => (
                "apply.audit.retired_rows_present",
                "database",
                "a pre-simplification registry_audit or registry_audit_head table still carries rows that installing this schema would discard. The exact target remains pinned in maintenance; archive the retained rows through operator recovery (for example, copy them out with psql or pg_dump --table before they are dropped), then retry the exact pinned target, or retry the same apply with --acknowledge-retired-audit-discard to accept discarding them",
                DiagnosticArtifact::DatabaseMigration,
                SuggestedAction::ArchiveRetiredAuditRows,
            ),
        },
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
        package_digest: inspected.package_digest().to_owned(),
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
        package_digest: inspected.package_digest().to_owned(),
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
    migration_reconcile_report(outcome)
}

fn migration_reconcile_report(
    outcome: ReconcileLifecycleOutcome,
) -> Result<MigrationReconcileSuccessReport, FailureReport> {
    // Assessment always returns Ok from `reconcile_lifecycle::run`, even when
    // the outcome is unresolvable: only `--execute` routes that outcome
    // through `ReconcileError::NotExecutable`. Reporting it here too keeps an
    // unresolvable assessment a refusal instead of a scriptable `ok: true`.
    // The assessed findings are fixed, value-free catalog and plan names, and
    // they are what an operator weighs before restoring a backup, so the
    // refusal carries them instead of dropping them with the success report.
    if outcome.outcome == ReconcileOutcome::Unresolvable.as_str() {
        let mut failure = reconcile_lifecycle_failure(ReconcileLifecycleError::Reconcile(
            ReconcileError::NotExecutable(ReconcileOutcome::Unresolvable),
        ));
        if let Some(diagnostic) = failure.diagnostics.first_mut() {
            diagnostic.message = format!(
                "{}; unresolvable reason: {}; target catalog finding: {}; active catalog finding: {}",
                diagnostic.message,
                optional(outcome.unresolvable_reason),
                optional(outcome.target_catalog_finding),
                optional(outcome.active_catalog_finding),
            );
        }
        return Err(failure);
    }
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
        ReconcileLifecycleError::ActiveRegistry(error) => {
            return active_registry_failure("migration reconcile", "migration.reconcile", error);
        }
        ReconcileLifecycleError::ActivePackage(PackageError::ExpectedDigestMismatch(mismatch)) => {
            return package_pin_failure(
                "migration reconcile",
                "migration.reconcile.package.refused",
                "package",
                &mismatch,
            );
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
        ReconcileLifecycleError::ActiveRegistry(_) => unreachable!("handled before match"),
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
        ReconcileLifecycleError::Audit => (
            "migration.reconcile.audit.unavailable",
            "audit",
            "the migration reconciliation audit destination could not be opened; check the audit path and its directory permissions",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
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
    let error = match error {
        RuntimePackageInspectionError::RuntimeConfig(error) => {
            return runtime_config_failure(command, prefix, error);
        }
        RuntimePackageInspectionError::SharedPackage(message) => {
            return FailureReport {
                ok: false,
                command,
                diagnostics: vec![tool_diagnostic(
                    diagnostic(
                        &format!("{prefix}.package.integrity_refused"),
                        "package",
                        &message,
                    ),
                    DiagnosticArtifact::VerifiedPackage,
                    SuggestedAction::VerifyPackageIntegrity,
                )],
            };
        }
        other => other,
    };
    let (code, path, message, artifact, action) = match error {
        RuntimePackageInspectionError::RuntimeConfigPath => (
            format!("{prefix}.runtime_config.path_invalid"),
            "runtimeConfig",
            "the runtime configuration path must be absolute",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        RuntimePackageInspectionError::RuntimeConfig(_) => unreachable!("handled before match"),
        RuntimePackageInspectionError::SharedPackage(_) => unreachable!("handled before match"),
        RuntimePackageInspectionError::Package(error) => {
            let (suffix, action) = package_refusal(&error);
            (
                format!("{prefix}.package.{suffix}"),
                "package",
                package_refusal_message(&error, "the configured package was refused"),
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

/// The diagnostic code suffix and next action for a refused package, shared
/// by every command that reads one.
fn package_refusal(error: &PackageError) -> (&'static str, SuggestedAction) {
    match error {
        PackageError::UnsafePath => ("path_refused", SuggestedAction::VerifyPackagePath),
        PackageError::Permissions => (
            "permissions_refused",
            SuggestedAction::VerifyPackagePermissions,
        ),
        PackageError::Binding => ("binding_refused", SuggestedAction::VerifyPackageBinding),
        PackageError::LegacyFormat => ("legacy_format", SuggestedAction::CorrectPackageBuild),
        PackageError::Envelope
        | PackageError::ExpectedDigestMismatch(_)
        | PackageError::Closure
        | PackageError::Integrity
        | PackageError::CanonicalJson
        | PackageError::Derivation
        | PackageError::MigrationPlan
        | PackageError::ReviewedMigration(_) => {
            ("integrity_refused", SuggestedAction::VerifyPackageIntegrity)
        }
        PackageError::Bounds | PackageError::Read => {
            ("package_refused", SuggestedAction::VerifyPackageIntegrity)
        }
    }
}

fn package_refusal_action(error: &PackageError) -> SuggestedAction {
    match error {
        PackageError::UnsafePath => SuggestedAction::VerifyPackagePath,
        PackageError::Permissions => SuggestedAction::VerifyPackagePermissions,
        PackageError::Binding => SuggestedAction::VerifyPackageBinding,
        _ => SuggestedAction::VerifyPackageIntegrity,
    }
}

/// A package in the retired format is refused with the command that rebuilds
/// it; every other refusal keeps the caller's value-free sentence.
fn package_refusal_message(error: &PackageError, message: &'static str) -> &'static str {
    match error {
        PackageError::LegacyFormat => registry_breg::package::LEGACY_PACKAGE_FORMAT,
        _ => message,
    }
}

/// The configured active package does not match the runtime file's
/// `package.expectedDigest` pin. The refusal keeps the command's own package
/// code and path and names both digests, which are package identities and not
/// secrets.
fn package_pin_failure(
    command: &'static str,
    code: &str,
    path: &str,
    mismatch: &PackageDigestMismatch,
) -> FailureReport {
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(code, path, &mismatch.to_string()),
            DiagnosticArtifact::VerifiedPackage,
            SuggestedAction::VerifyPackageIntegrity,
        )],
    }
}

/// A lifecycle that could not bind the configured active package to the
/// identity the database records. Each refusal names the next command.
fn active_registry_failure(
    command: &'static str,
    prefix: &str,
    error: ActiveRegistryError,
) -> FailureReport {
    let (suffix, path, message, artifact, action) = match error {
        ActiveRegistryError::Unavailable => (
            "unavailable",
            "database",
            "the database could not be read to find its active registry; check that database.migrationUrlRef reaches PostgreSQL as the migration role, then rerun the command",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ActiveRegistryError::InProgress => (
            "in_progress",
            "database",
            "another session holds the exclusive migration lock, so an apply, an adoption, or a migration reconcile is in progress; rerun the command once it releases",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::RetryAfterMigrationLockReleases,
        ),
        ActiveRegistryError::Uninitialized => (
            "uninitialized",
            "database",
            "the database records no activated registry for this package; run `bregctl apply --initial` first",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::VerifyMigrationAuthority,
        ),
        ActiveRegistryError::Unrecognized => (
            "unrecognized",
            "database",
            "the database holds registry state this release does not recognise, such as state written by a release older than its immediate predecessor; a release reads only the state its predecessor wrote, so upgrade one release at a time",
            DiagnosticArtifact::DatabaseMigration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ActiveRegistryError::DatabaseMismatch => (
            "database_mismatch",
            "identity.databaseId",
            "the database records another database id than identity.databaseId; point database.migrationUrlRef at the database identity.databaseId names, or correct identity.databaseId",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
        ActiveRegistryError::PackageMismatch => (
            "package_mismatch",
            "package.root",
            "package.root names a package the database does not run; set package.root to the active package directory, which `bregctl status` reports",
            DiagnosticArtifact::RuntimeConfiguration,
            SuggestedAction::CorrectRuntimeConfiguration,
        ),
    };
    FailureReport {
        ok: false,
        command,
        diagnostics: vec![tool_diagnostic(
            diagnostic(&format!("{prefix}.active_registry.{suffix}"), path, message),
            artifact,
            action,
        )],
    }
}

/// A `--baseline-package` directory that `test` or `package` refused.
fn baseline_package_failure(command: &'static str, error: PackageError) -> FailureReport {
    let (suffix, action) = package_refusal(&error);
    candidate_failure(
        command,
        &format!("package.baseline.{suffix}"),
        "baselinePackage",
        package_refusal_message(
            &error,
            "the baseline package was refused; name the chain tip package directory with --baseline-package as an absolute path",
        ),
        DiagnosticArtifact::BaselinePackage,
        action,
    )
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
    let (suffix, action) = package_refusal(&error);
    diff_failure_with_action(
        &format!("diff.baseline.{suffix}"),
        "baseline",
        package_refusal_message(&error, "the baseline package was refused"),
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

const REMOVED_VALUES_RETAINED_CODE: &str = "diff.history.removed_values_retained";

/// Removing a field or an entity drops its live column or table, but every
/// revision snapshot recorded before the change still holds the values in the
/// retained history. Each removal says so, so an operator does not mistake a
/// package change for erasure.
fn removed_value_findings(diff: &CompiledRegistryDiff) -> Vec<Diagnostic> {
    diff.changes
        .iter()
        .filter(|change| {
            matches!(
                change.change.code,
                registry_breg::package::CompiledRegistryChangeCode::FieldRemoved
                    | registry_breg::package::CompiledRegistryChangeCode::EntityRemoved
            )
        })
        .map(|change| Diagnostic {
            severity: DiagnosticSeverity::Finding,
            code: REMOVED_VALUES_RETAINED_CODE.to_owned(),
            path: diff_change_path(&change.change),
            message: "removing this from the package is not erasure: the values stay in every \
                      revision snapshot recorded before the change; only `bregctl history erase` \
                      removes them, one record's revisions at a time"
                .to_owned(),
        })
        .collect()
}

/// List the selected changes as `code at target`, with the sentence a code
/// carries beyond its name, so a refusal names what an adopter has to act on.
fn rendered_changes(
    changes: &[registry_breg::package::CompiledRegistryChange],
    selected: impl Fn(&registry_breg::package::CompiledRegistryChange) -> bool,
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

fn change_code_name(code: registry_breg::package::CompiledRegistryChangeCode) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{code:?}"))
}

fn diff_change_path(change: &registry_breg::package::CompiledRegistryChange) -> String {
    match (
        change.target.entity_id.as_deref(),
        change.target.member_id.as_deref(),
    ) {
        (Some(entity), Some(member)) => format!("changes.{entity}.{member}"),
        (Some(entity), None) => format!("changes.{entity}"),
        (None, _) => "changes.registry".to_owned(),
    }
}

/// Whether the operator asked for the command tree rather than an operation.
/// `--help` and `-h` are recognized in any position, matching clap's own
/// help flags. A bare `help` token only counts in the subcommand position,
/// reached by skipping past the global `--format` flag when it comes first,
/// so `help --format json` and `--format json help` render the catalog while
/// a value spelled "help" carried by a later argument, such as the project
/// path in `explain access help`, is never mistaken for a help request.
fn help_requested(arguments: &[OsString]) -> bool {
    if arguments
        .iter()
        .skip(1)
        .any(|argument| argument == "--help" || argument == "-h")
    {
        return true;
    }
    let mut index = 1;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "--format" {
            index += 2;
            continue;
        }
        if argument
            .to_str()
            .is_some_and(|value| value.starts_with("--format="))
        {
            index += 1;
            continue;
        }
        return argument == "help";
    }
    false
}

fn requested_json(arguments: &[OsString]) -> bool {
    arguments.iter().enumerate().any(|(index, argument)| {
        argument == "--format=json"
            || (argument == "--format"
                && arguments.get(index + 1).is_some_and(|next| next == "json"))
    })
}

/// Describe a command line clap refused by the error kind and the argument
/// name only, followed by the usage clap renders from the declared arguments.
/// Clap's own message is never repeated because it quotes the rejected token,
/// which may carry an operator value such as a change reference that is
/// otherwise recorded only as a keyed hash. A value one of our own parsers
/// refused is described by that parser's reason instead, as long as the reason
/// does not repeat the value; a reason that does not name the argument follows
/// it. The text is plain, without terminal styling.
fn usage_message(error: &clap::Error, arguments: &[OsString]) -> String {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let argument = refused_argument(error, arguments);
    let named = |text: &str| match &argument {
        Some(argument) => format!("{text} {argument}"),
        None => text.to_owned(),
    };
    let mut message = match error.kind() {
        ErrorKind::ValueValidation => {
            let general = named("invalid value for");
            let flag = argument
                .as_deref()
                .and_then(|name| name.split_whitespace().next());
            match validator_reason(error) {
                Some(reason) if flag.is_none_or(|flag| reason.contains(flag)) => reason,
                Some(reason) => format!("{general}: {reason}"),
                None => general,
            }
        }
        ErrorKind::InvalidValue => {
            // The possible values are the declared ones, never the operator's.
            let general = named("invalid value for");
            match error.get(ContextKind::ValidValue) {
                Some(ContextValue::Strings(values)) if !values.is_empty() => {
                    format!("{general}\n  [possible values: {}]", values.join(", "))
                }
                _ => general,
            }
        }
        ErrorKind::UnknownArgument => named("unexpected argument"),
        ErrorKind::InvalidSubcommand => "unrecognized subcommand".to_owned(),
        ErrorKind::NoEquals => named("an equals sign is required for"),
        ErrorKind::TooManyValues | ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
            named("wrong number of values for")
        }
        ErrorKind::ArgumentConflict => named("conflicting use of"),
        ErrorKind::MissingRequiredArgument => named("missing required argument"),
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            "missing subcommand".to_owned()
        }
        ErrorKind::InvalidUtf8 => "invalid UTF-8 in the command arguments".to_owned(),
        _ => "invalid command arguments".to_owned(),
    };
    // Clap renders the usage from the declared arguments, never their values.
    if let Some(ContextValue::StyledStr(usage)) = error.get(ContextKind::Usage) {
        message.push_str(&format!("\n\n{usage}"));
    }
    message.push_str("\n\nFor more information, try '--help'.");
    message
}

/// The reason one of our own value parsers gave, kept only while it does not
/// repeat the rejected value.
fn validator_reason(error: &clap::Error) -> Option<String> {
    use clap::error::{ContextKind, ContextValue};
    let reason = std::error::Error::source(error)?.to_string();
    let rejected = match error.get(ContextKind::InvalidValue) {
        Some(ContextValue::String(value)) => value.as_str(),
        _ => return None,
    };
    let repeats = !rejected.is_empty() && reason.contains(rejected);
    (!reason.is_empty() && !repeats).then_some(reason)
}

/// Options whose values bregctl records only as a keyed hash.
const HASHED_VALUE_OPTIONS: [&str; 2] = ["--operator-reference", "--reason"];

/// The name of the argument clap refused, without any value. A declared
/// argument is named as clap renders its definition. An unknown argument is
/// the operator's own token, so it is named only when it has the shape of a
/// long option, only up to any `=`, and never when it sits where an option
/// expects its value, since `--operator-reference --change-42` refuses the
/// value itself as an unknown argument. Nor is it named on a command line
/// that passes an option recorded only as a keyed hash, since an unquoted
/// `--operator-reference change --private-42` refuses a continuation of that
/// value.
fn refused_argument(error: &clap::Error, arguments: &[OsString]) -> Option<String> {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    let names = match error.get(ContextKind::InvalidArg)? {
        ContextValue::String(name) => vec![name.as_str()],
        ContextValue::Strings(names) => names.iter().map(String::as_str).collect(),
        _ => return None,
    };
    let names = names
        .into_iter()
        .filter_map(|name| {
            if error.kind() == ErrorKind::UnknownArgument {
                let option = name.split('=').next()?;
                let flag = option.strip_prefix("--")?;
                let shaped = !flag.is_empty()
                    && flag.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '-'
                    });
                (shaped
                    && !follows_a_value_option(option, arguments)
                    && !passes_a_hashed_value(arguments))
                .then(|| option.to_owned())
            } else {
                Some(name.to_owned())
            }
        })
        .collect::<Vec<_>>();
    (!names.is_empty()).then(|| names.join(", "))
}

/// Whether the command line passes an option whose value is recorded only as a
/// keyed hash, in either the separate or the attached form.
fn passes_a_hashed_value(arguments: &[OsString]) -> bool {
    arguments
        .iter()
        .filter_map(|argument| argument.to_str())
        .any(|token| {
            HASHED_VALUE_OPTIONS
                .iter()
                .any(|option| token.split('=').next() == Some(option))
        })
}

/// Whether a token starting with `option` directly follows an option that
/// takes a value anywhere in the command tree, which makes it that value.
fn follows_a_value_option(option: &str, arguments: &[OsString]) -> bool {
    fn value_options(command: &clap::Command, names: &mut BTreeSet<String>) {
        for argument in command.get_arguments() {
            if argument.get_action().takes_values() {
                if let Some(long) = argument.get_long() {
                    names.insert(format!("--{long}"));
                }
                if let Some(short) = argument.get_short() {
                    names.insert(format!("-{short}"));
                }
            }
        }
        for subcommand in command.get_subcommands() {
            value_options(subcommand, names);
        }
    }
    let mut names = BTreeSet::new();
    value_options(&command(), &mut names);
    arguments.windows(2).any(|pair| {
        pair[1]
            .to_str()
            .is_some_and(|token| token.split('=').next() == Some(option))
            && pair[0].to_str().is_some_and(|flag| names.contains(flag))
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
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts: files
            .iter()
            .map(|(path, bytes)| artifact_report(path, init_media_type(path), bytes))
            .collect(),
        explanation: None,
        next_steps: init_next_steps(destination),
    })
}

/// What a reader does after `init`, named against the directory just written.
///
/// The example project reports findings and carries a reserved base IRI, both
/// on purpose. A reader who is told neither reads a finding as a mistake and
/// carries the reserved identity into a real package, so `init` says which of
/// the two it left standing for teaching and which one has to go before a
/// production package.
fn init_next_steps(destination: &Path) -> Vec<String> {
    let readme = destination.join("README.md");
    vec![
        format!(
            "read {}, then run 'bregctl check {}'",
            readme.display(),
            destination.display()
        ),
        format!(
            "leave the findings above as they are; the example operator profile lists a whole collection and the example evidence-source profile looks up any record, both on purpose, and {} says where to narrow them",
            readme.display()
        ),
        format!(
            "replace canonicalBaseIri in {} before you build a production package; the example value is a reserved .invalid name that never resolves",
            destination.join("registry.yaml").display()
        ),
    ]
}

fn check(project_path: &Path, profile: ProfileArg) -> Result<SuccessReport, FailureReport> {
    let compiled = compile(project_path, profile, "check")?;
    let mut findings = compiler_findings(&compiled);
    findings.extend(compiled.entities().values().flat_map(|entity| {
        entity.fields.values().filter_map(move |field| {
            field.pattern.as_ref().map(|_| ToolDiagnostic {
                severity: DiagnosticSeverity::Finding,
                code: "field.pattern.unverified_offline".to_owned(),
                artifact: DiagnosticArtifact::RegistryProject,
                path: format!("entities[{}].fields[{}].pattern", entity.id, field.id),
                message: "Offline check validates pattern structure and bounds only. Run bregctl test against disposable PostgreSQL to verify native pattern syntax and storage behavior.".to_owned(),
                suggested_action: SuggestedAction::RunSchemaTest,
            })
        })
    }));
    Ok(SuccessReport {
        ok: true,
        command: "check",
        profile,
        revision: Some(compiled.revision().to_owned()),
        registry_revision: Some(compiled.revision().to_owned()),
        package_digest: None,
        findings,
        artifacts: Vec::new(),
        explanation: None,
        next_steps: Vec::new(),
    })
}

/// Verify a closed package against its sums and rederive its registry
/// revision, with no database, runtime configuration, or test receipt.
fn check_package(package_root: &Path) -> Result<SuccessReport, FailureReport> {
    let inspected = inspect_package_integrity(package_root).map_err(|error| {
        let (suffix, action) = package_refusal(&error);
        FailureReport {
            ok: false,
            command: "check",
            diagnostics: vec![tool_diagnostic(
                diagnostic(
                    &format!("check.package.{suffix}"),
                    "package",
                    package_refusal_message(&error, "the package was refused"),
                ),
                DiagnosticArtifact::VerifiedPackage,
                action,
            )],
        }
    })?;
    let revision = inspected.registry().revision().to_owned();
    Ok(SuccessReport {
        ok: true,
        command: "check",
        profile: ProfileArg::Production,
        revision: Some(revision.clone()),
        registry_revision: Some(revision),
        package_digest: Some(inspected.package_digest().to_owned()),
        findings: Vec::new(),
        artifacts: Vec::new(),
        explanation: None,
        next_steps: Vec::new(),
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
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts,
        explanation: Some(json!({
            "changed": changed,
            "modules": reports,
        })),
        next_steps: Vec::new(),
    })
}

fn generate_requested(args: &GenerateArgs) -> Result<SuccessReport, FailureReport> {
    let fail = |message: &str| {
        source_failure(
            "generate",
            diagnostic("evidence_source.arguments", "arguments", message),
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        )
    };
    if args.artifact != ArtifactSelector::EvidenceSource {
        if args.access_profile.is_some()
            || args.entity.is_some()
            || !args.selectors.is_empty()
            || !args.fields.is_empty()
            || args.source_id.is_some()
            || args.connection.is_some()
        {
            return Err(fail(
                "source selection flags apply only to generate evidence-source",
            ));
        }
        return generate(
            args.artifact,
            &args.project,
            profile(args.production),
            &args.output,
        );
    }
    let required = |value: &Option<String>, flag: &str| {
        value
            .clone()
            .ok_or_else(|| fail(&format!("generate evidence-source requires {flag}")))
    };
    let options = registry_breg::evidence_source::EvidenceSourceOptions {
        access_profile: required(&args.access_profile, "--access-profile")?,
        entity: required(&args.entity, "--entity")?,
        selectors: args.selectors.clone(),
        fields: args.fields.clone(),
        source_id: required(&args.source_id, "--source-id")?,
        connection: required(&args.connection, "--connection")?,
    };
    let profile = profile(args.production);
    let compiled = compile(&args.project, profile, "generate")?;
    let export = registry_breg::evidence_source::export_evidence_source(&compiled, &options)
        .map_err(|diagnostic| {
            source_failure(
                "generate",
                diagnostic,
                DiagnosticArtifact::RegistryProject,
                SuggestedAction::CorrectAuthoringSource,
            )
        })?;
    write_artifacts(&args.output, &export.artifacts).map_err(|diagnostic| {
        source_failure(
            "generate",
            diagnostic,
            DiagnosticArtifact::GeneratedArtifacts,
            SuggestedAction::RetryArtifactGeneration,
        )
    })?;
    Ok(SuccessReport {
        ok: true,
        command: "generate",
        profile,
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts: export
            .artifacts
            .iter()
            .map(|artifact| artifact_report(&artifact.path, &artifact.media_type, &artifact.bytes))
            .collect(),
        explanation: Some(
            json!({"sourceId":options.source_id,"connection":options.connection,"behaviorRevision":export.behavior_revision,"selectorProfiles":export.selector_profiles,"additionalIdentityFields":export.identity_fields}),
        ),
        next_steps: vec![],
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
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts,
        explanation: None,
        next_steps: Vec::new(),
    })
}

fn planner_test(args: &ProjectPlannerTestArgs) -> Result<PlannerTestSuccessReport, FailureReport> {
    const COMMAND: &str = "project planner-test";
    let compiled = compile(&args.project, ProfileArg::Authoring, COMMAND)?;
    if args.action.is_some() {
        return action_handler_test::run(args, &compiled);
    }
    let entity_id = args.entity.as_deref().ok_or_else(|| {
        planner_test_failure(
            "planner_test.entity.required",
            "entity",
            "select a request entity or action",
        )
    })?;
    let request_path = args.request.as_ref().ok_or_else(|| {
        planner_test_failure(
            "planner_test.request.required",
            "request",
            "provide a synthetic request file",
        )
    })?;
    let entity = compiled.entities().get(entity_id).ok_or_else(|| {
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
        request_path,
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

    let candidate = registry_breg::rhai_planner::plan_change_request_effects(
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
                    registry_breg::rhai_planner::CandidateChangeRequestMutation::Set {
                        field,
                        ..
                    }
                    | registry_breg::rhai_planner::CandidateChangeRequestMutation::Clear {
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
                    registry_breg::rhai_planner::CandidateChangeRequestTargetBinding::Existing {
                        ..
                    } => "existing",
                    registry_breg::rhai_planner::CandidateChangeRequestTargetBinding::ReservedCreate {
                        ..
                    } => "reserved_create",
                },
                operation: operation_wire_name(effect.operation),
                fields,
                depends_on,
            })
        })
        .collect::<Result<Vec<_>, FailureReport>>()?;
    Ok(PlannerTestSuccessReport {
        ok: true,
        command: COMMAND,
        compiled_revision: compiled.revision().to_owned(),
        request_entity: entity.id.clone(),
        action: None,
        refusal: None,
        assertions_passed: None,
        planner: Some(PlannerTestIdentityReport {
            kind: "rhai",
            abi: planner.abi.clone(),
            script_sha256: planner.script_sha256.clone(),
        }),
        handler: None,
        counts: PlannerTestCountReport {
            effects: effects.len(),
            field_mutations,
            dependencies: dependency_count,
        },
        effects,
    })
}

fn bounded_planner_test_value(value: &Value, depth: usize) -> bool {
    use registry_breg::rhai_planner::{
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

/// `apiVersion` for every `bregctl explain` payload, versioned as a whole: any change
/// to a pinned object's shape in one of the nine kinds bumps this version.
const EXPLAIN_API_VERSION: &str = "registry.registrystack.org/breg-explain/v1alpha3";

/// Which `explanation` kind a subject (and, for `access`, whether a scenario ran)
/// produces. Kept beside `explain_envelope` because the two always travel together.
fn explain_kind(subject: ExplainSubject, scenario_present: bool) -> &'static str {
    match subject {
        ExplainSubject::Model => "ModelExplanation",
        ExplainSubject::Access if scenario_present => "AccessPreview",
        ExplainSubject::Access => "AccessExplanation",
        ExplainSubject::Routes => "RoutesExplanation",
        ExplainSubject::Queries => "QueriesExplanation",
        ExplainSubject::Actions => "ActionsExplanation",
        ExplainSubject::ChangeRequests => "ChangeRequestsExplanation",
        ExplainSubject::Events => "EventsExplanation",
        ExplainSubject::Lifecycle => "LifecycleExplanation",
    }
}

/// Insert the envelope's `apiVersion` and `kind` into an already-serialized explanation,
/// the same post-serialization technique `explain_routes` uses for its `kind` discriminator
/// (see the comment there for why). The envelope cannot live on `SuccessReport` itself:
/// `explanation` is a slot `project lock` and `generate` also populate, and it cannot live
/// on a `registry-breg` type either: `AccessExplanation` and `AccessPreview` are runtime
/// types, and `CompiledEventDeliveryInventory` is `deny_unknown_fields` and round-trips
/// through package inventories, so an extra field on any of them would either misdescribe
/// an unrelated report or break an unrelated contract.
fn explain_envelope(kind: &'static str, mut explanation: Value) -> Value {
    explanation
        .as_object_mut()
        .expect("every explanation payload serializes as an object")
        .extend([
            ("apiVersion".to_string(), Value::from(EXPLAIN_API_VERSION)),
            ("kind".to_string(), Value::from(kind)),
        ]);
    explanation
}

/// The refusal every `explain` argument mistake reports: a wrong subject for
/// `--scenario`, a missing PROJECT, a PROJECT given to the one subject that
/// takes none, or an unreadable scenario file.
fn explain_usage_error(diagnostic: Diagnostic) -> FailureReport {
    FailureReport {
        ok: false,
        command: "explain",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::CorrectCommandUsage,
        )],
    }
}

/// The refusal a payload that will not serialize reports.
fn explain_render_error() -> FailureReport {
    FailureReport {
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
    }
}

/// `explain lifecycle`: the request lifecycle the engine enforces, reported
/// without compiling anything.
///
/// PROJECT is refused rather than ignored here. The lifecycle is engine
/// behaviour, so accepting a project would teach a reader that some project
/// could change it, and compiling one would let an unrelated authoring error
/// refuse an answer that never depended on the project in the first place.
///
/// `--production` is refused for the same reason. It selects the production
/// package-closure check, which runs against a compiled project; a report
/// that compiled nothing and still named `profile: production` would state
/// that check had passed when it never ran.
fn explain_lifecycle(
    profile: ProfileArg,
    project_path: Option<&Path>,
    scenario_path: Option<&Path>,
) -> Result<SuccessReport, FailureReport> {
    if project_path.is_some() {
        return Err(explain_usage_error(diagnostic(
            "lifecycle.project.unused",
            "project",
            "explain lifecycle reports the engine's request lifecycle, which no registry project changes; run it with no PROJECT",
        )));
    }
    if matches!(profile, ProfileArg::Production) {
        return Err(explain_usage_error(diagnostic(
            "lifecycle.profile.unused",
            "production",
            "explain lifecycle compiles no project, so it enforces no production package closure; run it without --production",
        )));
    }
    if scenario_path.is_some() {
        return Err(explain_usage_error(diagnostic(
            "access.scenario.subject",
            "scenario",
            "--scenario is available only for explain access",
        )));
    }
    let lifecycle = serde_json::to_value(registry_breg::lifecycle::request_lifecycle())
        .map_err(|_| explain_render_error())?;
    let explanation = Value::Object(serde_json::Map::from_iter([(
        "lifecycles".to_owned(),
        Value::Array(vec![lifecycle]),
    )]));
    Ok(SuccessReport {
        ok: true,
        command: "explain",
        profile,
        revision: None,
        registry_revision: None,
        package_digest: None,
        findings: Vec::new(),
        artifacts: Vec::new(),
        explanation: Some(explain_envelope(
            explain_kind(ExplainSubject::Lifecycle, false),
            explanation,
        )),
        next_steps: Vec::new(),
    })
}

fn explain(
    subject: ExplainSubject,
    project_path: Option<&Path>,
    profile: ProfileArg,
    scenario_path: Option<&Path>,
) -> Result<SuccessReport, FailureReport> {
    if matches!(subject, ExplainSubject::Lifecycle) {
        return explain_lifecycle(profile, project_path, scenario_path);
    }
    let project_path = project_path.ok_or_else(|| {
        explain_usage_error(diagnostic(
            "explain.project.missing",
            "project",
            "name the registry project directory to explain; only explain lifecycle runs without one",
        ))
    })?;
    let compiled = compile(project_path, profile, "explain")?;
    let scenario = if let Some(path) = scenario_path {
        if !matches!(subject, ExplainSubject::Access) {
            return Err(explain_usage_error(diagnostic(
                "access.scenario.subject",
                "scenario",
                "--scenario is available only for explain access",
            )));
        }
        let bytes =
            read_bounded_source_file(path, "access.scenario.unavailable", "scenario", 65_536)
                .map_err(explain_usage_error)?;
        let source = parse_json_strict(&bytes).map_err(|_| explain_usage_error(diagnostic("access.scenario.invalid", "scenario", "provide a strict JSON access scenario with synthetic claims; duplicate keys and malformed JSON are refused")))?;
        let scenario = serde_json::from_value(source).map_err(|_| explain_usage_error(diagnostic("access.scenario.invalid", "scenario", "use entity, accessProfile, operation, optional readPath, and claims; claims accepts principalClaim, principal, scopes, purpose, directClaims, actorKind, requesterClient")))?;
        Some(
            registry_breg::access_preview::preview_access(&compiled, scenario).map_err(
                |message| {
                    explain_usage_error(diagnostic("access.scenario.invalid", "scenario", message))
                },
            )?,
        )
    } else {
        None
    };
    let scenario_present = scenario.is_some();
    let explanation = match subject {
        ExplainSubject::Model => explain_model(&compiled),
        ExplainSubject::Access => {
            if let Some(scenario) = scenario {
                serde_json::to_value(scenario)
            } else {
                serde_json::to_value(registry_breg::access::explain_access(&compiled))
            }
        }
        ExplainSubject::Routes => explain_routes(&compiled),
        ExplainSubject::Queries => explain_queries(&compiled),
        ExplainSubject::Actions => explain_actions(&compiled),
        ExplainSubject::ChangeRequests => explain_change_requests(&compiled),
        ExplainSubject::Events => serde_json::to_value(compiled.event_deliveries()),
        ExplainSubject::Lifecycle => unreachable!("lifecycle returns before the project compiles"),
    }
    .map_err(|_| explain_render_error())?;
    let explanation = explain_envelope(explain_kind(subject, scenario_present), explanation);
    Ok(SuccessReport {
        ok: true,
        command: "explain",
        profile,
        revision: Some(compiled.revision().to_owned()),
        registry_revision: None,
        package_digest: None,
        findings: compiler_findings(&compiled),
        artifacts: Vec::new(),
        explanation: Some(explanation),
        next_steps: Vec::new(),
    })
}

fn compile(
    project_path: &Path,
    profile: ProfileArg,
    command: &'static str,
) -> Result<registry_breg::CompiledRegistry, FailureReport> {
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
) -> Result<registry_breg::CompiledRegistry, FailureReport> {
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
    let project_directory = validate_project_directory(project_path)?;
    let project_bytes = read_bounded_source_file(
        &project_path.join("registry.yaml"),
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    let project = parse_project_yaml(&project_bytes).map_err(first_diagnostic)?;
    let project_assets = load_project_planner_asset_files(&project_directory, &project)?;
    let modules = load_module_files(project_path, &project)?
        .into_iter()
        .map(|source| {
            let ModuleSource {
                id,
                bytes,
                directory,
            } = source;
            let module = parse_module_yaml(&bytes).map_err(first_diagnostic)?;
            ensure_module_id_matches_directory(&module.id, &id)?;
            let assets = load_module_asset_files(&directory, &id, &module)?;
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
    let project_directory = validate_project_directory(project_path)?;
    let project_bytes = read_bounded_source_file(
        &project_path.join("registry.yaml"),
        "source.project.missing",
        "registry.yaml",
        AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
    )?;
    let project = parse_project_yaml(&project_bytes).map_err(first_diagnostic)?;
    let project_assets = load_project_planner_asset_files(&project_directory, &project)?;
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
        .map(|source| {
            let ModuleSource {
                id: directory_id,
                bytes,
                directory,
            } = source;
            let module = parse_module_yaml(&bytes).map_err(first_diagnostic)?;
            ensure_module_id_matches_directory(&module.id, &directory_id)?;
            let assets = load_module_asset_files(&directory, &directory_id, &module)?;
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
) -> Result<Vec<ModuleSource>, Diagnostic> {
    let locked: std::collections::BTreeSet<&str> = project
        .modules
        .iter()
        .map(|module| module.id.as_str())
        .collect();
    let modules = read_module_directory_names(project_path)?;
    for id in &modules.names {
        if !locked.contains(id.as_str()) {
            return Err(diagnostic(
                "source.modules.unlocked",
                "modules",
                "every authored module directory must be declared by the project module lock",
            ));
        }
    }
    read_module_yaml_files(modules)
}

/// The authored module directories a project holds, together with the `modules`
/// directory descriptor they were listed through, so the reads that follow open
/// each `module.yaml` under the directory that was listed rather than resolving
/// its pathname again. An absent `modules` directory means the project authored
/// none.
struct ModuleDirectories {
    directory: Option<SafeDir>,
    names: Vec<String>,
}

/// List the authored module directories a project holds, refusing an entry that
/// is not a directory or that traverses a symbolic link.
fn read_module_directory_names(project_path: &Path) -> Result<ModuleDirectories, Diagnostic> {
    let unreadable = || {
        diagnostic(
            "source.modules.unreadable",
            "modules",
            "module sources cannot be read",
        )
    };
    let invalid = || {
        diagnostic(
            "source.modules.invalid",
            "modules",
            "module sources must be directories and must not be symbolic links",
        )
    };
    let directory = match SafeDir::resolve(&project_path.join("modules")) {
        Ok(directory) => directory,
        Err(SafePathError::NotFound) => {
            return Ok(ModuleDirectories {
                directory: None,
                names: Vec::new(),
            })
        }
        Err(SafePathError::Unavailable) => return Err(unreadable()),
        Err(error) => {
            return Err(path_diagnostic(
                error,
                "source.modules.invalid",
                "project",
                "the project directory is not available",
                "the project directory must be a directory and must not be a symbolic link",
            ))
        }
    };
    let mut names = Vec::new();
    for entry in directory.read_entries().map_err(|_| unreadable())? {
        // Finder metadata is not an authored module. Ignore only this exact
        // regular file; every other unexpected entry remains fail-closed.
        if entry.name == ".DS_Store" && entry.is_file {
            continue;
        }
        if entry.is_symlink || !entry.is_dir {
            return Err(invalid());
        }
        let Some(name) = entry.name.to_str() else {
            return Err(diagnostic(
                "source.modules.invalid",
                "modules",
                "module source names must be valid UTF-8 identifiers",
            ));
        };
        names.push(name.to_owned());
    }
    names.sort();
    Ok(ModuleDirectories {
        directory: Some(directory),
        names,
    })
}

/// One authored module: its `module.yaml` bytes and the module directory
/// descriptor they were read through. The assets the module declares are read
/// through that same descriptor, so one captured module source never mixes
/// bytes from two trees.
struct ModuleSource {
    id: String,
    bytes: Vec<u8>,
    directory: SafeDir,
}

/// Read each listed module's `module.yaml` through the listed `modules`
/// directory, so the file read is the one under the directory whose entries
/// were checked, whatever the pathname reaches by now.
fn read_module_yaml_files(modules: ModuleDirectories) -> Result<Vec<ModuleSource>, Diagnostic> {
    let ModuleDirectories { directory, names } = modules;
    let Some(directory) = directory else {
        return Ok(Vec::new());
    };
    names
        .into_iter()
        .map(|id| {
            let report_path = format!("modules/{id}/module.yaml");
            let module_directory = directory.open_directory(OsStr::new(&id)).map_err(|error| {
                path_diagnostic(
                    error,
                    "source.module.missing",
                    &report_path,
                    "the required authoring source is not available",
                    "authoring sources must be regular files and must not be symbolic links",
                )
            })?;
            let entry = SafeEntry::in_directory(module_directory, OsStr::new("module.yaml"));
            let bytes = read_bounded_source_entry(
                &entry,
                "source.module.missing",
                &report_path,
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )?;
            Ok(ModuleSource {
                id,
                bytes,
                directory: entry.into_parent(),
            })
        })
        .collect()
}

fn discover_module_files(project_path: &Path) -> Result<Vec<ModuleSource>, Diagnostic> {
    read_module_yaml_files(read_module_directory_names(project_path)?)
}

fn load_project_planner_asset_files(
    project_directory: &SafeDir,
    project: &RegistryProject,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    let mut paths = project
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| {
                    (
                        planner.script.clone(),
                        format!("entities[{}].changeRequest.planner.script", entity.id),
                    )
                })
        })
        .collect::<BTreeMap<_, _>>();
    let mut wasm_module_paths = BTreeMap::new();
    for action in &project.actions {
        partition_handler_source(
            action.handler.as_ref().map(|handler| &handler.handler),
            &format!("actions[{}]", action.id),
            &mut paths,
            &mut wasm_module_paths,
        );
    }
    for entity in &project.entities {
        for hook in &entity.hooks {
            partition_handler_source(
                hook.handler.as_ref(),
                &format!("entities[{}].hooks[{}]", entity.id, hook.id),
                &mut paths,
                &mut wasm_module_paths,
            );
        }
    }
    let mut assets = load_planner_asset_files(project_directory, paths)?;
    assets.extend(load_wasm_module_asset_files(
        project_directory,
        wasm_module_paths,
    )?);
    for provider in &project.evidence_providers {
        let location = format!("evidenceProviders[{}].contracts", provider.id);
        if !registry_breg::action_evidence_contracts::valid_contract_path(&provider.contracts) {
            return Err(diagnostic(
                "source.evidence_contract.path_unsafe",
                &location,
                "Evidence contracts require normalized project-relative JSON paths",
            ));
        }
        let entry = open_asset_entry(
            project_directory,
            &provider.contracts,
            || {
                diagnostic(
                    "source.evidence_contract.path_unsafe",
                    &location,
                    "Evidence contracts require normalized project-relative JSON paths",
                )
            },
            |error| {
                path_diagnostic(
                    error,
                    "source.evidence_contract.missing",
                    &location,
                    "the required Evidence contract is unavailable",
                    "Evidence contracts must be regular files without symbolic links",
                )
            },
        )?;
        let bytes = read_bounded_source_entry(
            &entry,
            "source.evidence_contract.missing",
            &location,
            registry_breg::action_evidence_contracts::MAX_EVIDENCE_CONTRACT_BYTES as u64,
        )?;
        if !assets.iter().any(|asset| asset.path == provider.contracts) {
            assets.push(CapturedModuleAssetSource {
                path: provider.contracts.clone(),
                bytes,
            });
        }
    }
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(assets)
}

/// Read a module's declared assets through the module directory descriptor the
/// module source was read from, so a `modules` ancestor replaced between the
/// listing and these reads cannot mix another tree's bytes into one captured
/// module.
fn load_module_asset_files(
    module_directory: &SafeDir,
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
            let report_path = format!("modules/{module_id}/{path}");
            let entry = open_asset_entry(
                module_directory,
                &path,
                || module_asset_path_diagnostic(module_id),
                |error| {
                    path_diagnostic(
                        error,
                        "source.module_asset.missing",
                        &report_path,
                        "the required authoring source is not available",
                        "authoring sources must be regular files and must not be symbolic links",
                    )
                },
            )?;
            let bytes = read_bounded_source_entry(
                &entry,
                "source.module_asset.missing",
                &report_path,
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
    let mut planner_paths = module
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| {
                    (
                        planner.script.clone(),
                        format!(
                            "modules[{module_id}].entities[{}].changeRequest.planner.script",
                            entity.id
                        ),
                    )
                })
        })
        .chain(module.extend_entities.iter().filter_map(|extension| {
            extension
                .change_request
                .as_ref()
                .and_then(|request| request.planner.as_ref())
                .map(|planner| {
                    (
                        planner.script.clone(),
                        format!(
                            "modules[{module_id}].extendEntities[{}].changeRequest.planner.script",
                            extension.entity
                        ),
                    )
                })
        }))
        .collect::<BTreeMap<_, _>>();
    let mut wasm_module_paths = BTreeMap::new();
    for action in &module.actions {
        partition_handler_source(
            action.handler.as_ref().map(|handler| &handler.handler),
            &format!("modules[{module_id}].actions[{}]", action.id),
            &mut planner_paths,
            &mut wasm_module_paths,
        );
    }
    for entity in &module.entities {
        for hook in &entity.hooks {
            partition_handler_source(
                hook.handler.as_ref(),
                &format!(
                    "modules[{module_id}].entities[{}].hooks[{}]",
                    entity.id, hook.id
                ),
                &mut planner_paths,
                &mut wasm_module_paths,
            );
        }
    }
    for extension in &module.extend_entities {
        for hook in &extension.hooks {
            partition_handler_source(
                hook.handler.as_ref(),
                &format!(
                    "modules[{module_id}].extendEntities[{}].hooks[{}]",
                    extension.entity, hook.id
                ),
                &mut planner_paths,
                &mut wasm_module_paths,
            );
        }
    }
    assets.extend(load_planner_asset_files(module_directory, planner_paths)?);
    assets.extend(load_wasm_module_asset_files(
        module_directory,
        wasm_module_paths,
    )?);
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(assets)
}

/// Split one handler's declared source reference into its asset family:
/// a Rhai script for rhai handlers, a WASM module for wasm handlers. An absent
/// reference contributes nothing here; the compiler refuses the incomplete
/// shape with its own diagnostic.
fn partition_handler_source(
    handler: Option<&HookHandlerSource>,
    declaring_path: &str,
    planner_paths: &mut BTreeMap<String, String>,
    wasm_module_paths: &mut BTreeMap<String, String>,
) {
    let Some(handler) = handler else { return };
    match handler {
        HookHandlerSource::Rhai { script, .. } => {
            planner_paths.insert(
                script.to_owned(),
                format!("{declaring_path}.handler.script"),
            );
        }
        HookHandlerSource::Wasm { module, .. } => {
            wasm_module_paths.insert(
                module.to_owned(),
                format!("{declaring_path}.handler.module"),
            );
        }
        HookHandlerSource::Url { .. } => {}
    }
}

/// Read the Rhai planner scripts declared by one authoring source through the
/// descriptor of the directory that source was read from, so the scripts come
/// from the tree the declaring file came from.
fn load_planner_asset_files(
    origin: &SafeDir,
    paths: BTreeMap<String, String>,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    paths
        .into_iter()
        .map(|(path, declaring_path)| {
            validate_rhai_planner_asset_path(&declaring_path, &path)?;
            let entry = open_asset_entry(
                origin,
                &path,
                || planner_asset_path_diagnostic(&declaring_path),
                |error| {
                    let mut diagnostic = path_diagnostic(
                        error,
                        "source.planner_asset.missing",
                        &declaring_path,
                        "the required authoring source is not available",
                        "authoring sources must be regular files and must not be symbolic links",
                    );
                    diagnostic.message.push_str(&format!(
                        "; referenced Rhai script: {path:?}, relative to its declaring project or module"
                    ));
                    diagnostic
                },
            )
            .map_err(|mut error| {
                error.message.push_str(&format!(
                    "; referenced Rhai script: {path:?}, relative to its declaring project or module"
                ));
                error
            })?;
            let bytes = read_bounded_source_entry(
                &entry,
                "source.planner_asset.missing",
                &declaring_path,
                MAX_RHAI_PLANNER_SOURCE_BYTES,
            )
            .map_err(|mut error| {
                error.message.push_str(&format!(
                    "; referenced Rhai script: {path:?}, relative to its declaring project or module"
                ));
                error
            })?;
            if bytes.is_empty() {
                return Err(diagnostic(
                    "source.planner_asset.bounds",
                    &declaring_path,
                    &format!("referenced Rhai script {path:?} must be a non-empty bounded regular file"),
                ));
            }
            Ok(CapturedModuleAssetSource { path, bytes })
        })
        .collect()
}

/// Read the WASM handler modules declared by one authoring source through the
/// descriptor of the directory that source was read from, so module bytes come
/// from the tree the declaring file came from.
fn load_wasm_module_asset_files(
    origin: &SafeDir,
    paths: BTreeMap<String, String>,
) -> Result<Vec<CapturedModuleAssetSource>, Diagnostic> {
    paths
        .into_iter()
        .map(|(path, declaring_path)| {
            validate_wasm_module_asset_path(&declaring_path, &path)?;
            let entry = open_asset_entry(
                origin,
                &path,
                || wasm_module_asset_path_diagnostic(&declaring_path),
                |error| {
                    let mut diagnostic = path_diagnostic(
                        error,
                        "source.wasm_module.missing",
                        &declaring_path,
                        "the required handler module is not available",
                        "handler modules must be regular files and must not be symbolic links",
                    );
                    diagnostic.message.push_str(&format!(
                        "; referenced WASM module: {path:?}, relative to its declaring project or module"
                    ));
                    diagnostic
                },
            )?;
            let bytes = read_bounded_source_entry(
                &entry,
                "source.wasm_module.missing",
                &declaring_path,
                registry_breg::wasm_handler::MAXIMUM_WASM_MODULE_BYTES as u64,
            )?;
            if bytes.is_empty() {
                return Err(diagnostic(
                    "source.wasm_module.bounds",
                    &declaring_path,
                    &format!("referenced WASM module {path:?} must be a non-empty bounded regular file"),
                ));
            }
            Ok(CapturedModuleAssetSource { path, bytes })
        })
        .collect()
}

fn validate_wasm_module_asset_path(
    declaring_path: &str,
    asset_path: &str,
) -> Result<(), Diagnostic> {
    if asset_path.is_empty()
        || asset_path.len() > MAX_RHAI_PLANNER_PATH_BYTES
        || asset_path.contains('\\')
        || asset_path.ends_with('/')
        || !asset_path.ends_with(".wasm")
    {
        return Err(wasm_module_asset_path_diagnostic(declaring_path));
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
        return Err(wasm_module_asset_path_diagnostic(declaring_path));
    }
    Ok(())
}

fn wasm_module_asset_path_diagnostic(declaring_path: &str) -> Diagnostic {
    diagnostic(
        "source.wasm_module.path_unsafe",
        declaring_path,
        "WASM handler modules must use bounded declaring-origin-relative .wasm paths",
    )
}

/// Open an asset named relative to an authoring origin through that origin's
/// held directory descriptor.
///
/// Every component is opened with `openat` and `O_NOFOLLOW`, and a path that is
/// absolute, climbs with `..`, or carries a prefix is refused rather than
/// walked, so the asset read reaches the tree the declaring source was read
/// from and no other.
fn open_asset_entry(
    origin: &SafeDir,
    asset_path: &str,
    unsafe_path: impl Fn() -> Diagnostic,
    unavailable: impl Fn(SafePathError) -> Diagnostic,
) -> Result<SafeEntry, Diagnostic> {
    let mut names = Vec::new();
    for component in Path::new(asset_path).components() {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return Err(unsafe_path()),
        }
    }
    let name = names.pop().ok_or_else(&unsafe_path)?;
    let mut directory = origin.try_clone().map_err(&unavailable)?;
    for part in names {
        directory = directory.open_directory(part).map_err(&unavailable)?;
    }
    Ok(SafeEntry::in_directory(directory, name))
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

`bregctl init` wrote this project. It is a working example, not a
blank page: every identifier is a placeholder chosen to be obviously synthetic,
and every file carries comments saying what a block does and what you change.

## Files

| File | What it holds |
| --- | --- |
| `registry.yaml` | The registry: its identity and package identity, the catalogue projection, one closed vocabulary, two entities, and three access profiles. Every command reads this file. |
| `modules/record-notes/module.yaml` | A module: a reusable part of the model, versioned on its own and pinned by content digest in the project's `modules` list. |
| `tests/journeys.yaml` | The requests `bregctl test` replays over HTTP against a throwaway database before a package is built. |
| `dev-clients.yaml` | The local callers `bregctl dev` registers with its token issuer: one client per access profile the journeys use. |
| `runtime.example.yaml` | An example of the operator's runtime configuration. No command reads it; copy it out of the project and replace every value. |

## What the example models

Two entities: `record-group` is public reference data, and `record` is the
internal record that points at a group through a `reference` field and carries a
`status` drawn from a closed vocabulary. Three access profiles read them: an
`operator` that runs the whole registry, a `record-reader` whose rows are
restricted by a claim on its own credentials, and an `evidence-source` that may
only look a record up by its `code`.

Replace this model with your own. The names are deliberately generic so that
nothing here reads as advice about what your registry should contain.

## Next commands

```sh
bregctl check .
bregctl explain queries .
bregctl explain events .
```

`check` compiles the project and reports problems and findings. It reports two
findings for this project on purpose: `access.profile.unrestricted_collection`,
because the `operator` profile can list every record, and
`access.profile.unrestricted_rows`, because the `evidence-source` profile can
look up any record by its code. The comment above each profile says how to
close it.

`explain` prints what the compiled project exposes, such as the query surface
each profile gets and the events the package would emit.

The `evidence-source` profile's lookup is what `generate evidence-source`
exports, so this project already produces an Evidence source definition:

```sh
mkdir exports
bregctl generate evidence-source . --access-profile evidence-source \
  --entity record --selector by-code --fields status \
  --source-id registry-status --connection registry \
  --output ./exports/registry-status
```

The dedicated `source` client in `dev-clients.yaml` binds only this lookup
profile and gets its own key on first start. This teaching profile can look up
any record by code: a supplied code is not a row authorization rule. Set your
intended readable fields and row boundaries before retaining records.

After stopping with `bregctl dev stop .`, use `bregctl dev export-client .
--client source --client-id-file PATH --assertion-key-file PATH` to copy its
existing pair into prepared owner-only directories. The command preserves
existing identical files and refuses conflicts; choose fresh paths and update
the consuming target if you explicitly replaced the development session.

The export refuses a destination that already exists and a parent directory that
does not, so the output path names a directory the command creates inside one
you made.

Edit `modules/record-notes/module.yaml`, then re-pin it:

```sh
bregctl project lock .
```

## Run it on your machine

`bregctl dev` starts this project as a working registry on loopback: PostgreSQL
and the pinned ThunderID issuer in Docker, and Base Registry Engine serving the
package it builds and tests from these files. It needs Docker and the installed
`breg` binary; client registrations come from `dev-clients.yaml`.

```sh
bregctl dev
bregctl dev stop
```

`bregctl test` alone replays `tests/journeys.yaml` over HTTP. It needs more
than the project: an empty PostgreSQL database, a runtime configuration built
from `runtime.example.yaml`, and one credential per journey step bound in a
credentials file. `dev` prepares all of that for a local run; the operate
documentation below walks through preparing them for a deployment.

## Documentation

- Configure a registry: <https://docs.registrystack.org/configure/breg/>
- Operate a registry: <https://docs.registrystack.org/operate/breg/>
- Every configuration key: <https://docs.registrystack.org/reference/breg-configuration/>
- `bregctl` commands: run `bregctl --help`.
"#;

const INIT_REGISTRY_PROJECT: &[u8] =
    br#"# The registry project: one document that decides the model, the access rules,
# and the catalogue description of a single registry. Every bregctl
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

# Package identity names the reviewed source revision a package is built
# from. A package carries no environment: the same package directory is
# applied unchanged to every environment, and each runtime file names its own
# `identity.environment` and `identity.instanceId`.
package:
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
      - {id: code, type: string, required: true, minLength: 1, maxLength: 64, classification: public}
      - {id: label, type: string, required: true, maxLength: 200, classification: public}
    constraints:
      - {id: record-group-code-unique, kind: unique, fields: [code]}

  # The registry's records. `group` is a reference: the server stores the target
  # record's identifier and refuses a value that names no `record-group`.
  # `status` is a vocabulary code drawn from the `record-status` list above.
  # Neither is `required`, so a create may omit it.
  #
  # An entity may also declare `hooks`, which project chosen fields of a
  # committed change to a URL destination the deployment binds by name. Each
  # hook declares `phase: after` and a handler such as
  # `{kind: url, destinationId: registry-events}`. This project declares none:
  # a package refuses to activate until the runtime configuration binds every
  # destination its URL handlers name. `bregctl dev` supplies local receiver
  # bindings; operated deployments bind their own.
  - id: record
    primaryDataset: generic-registry
    route: records
    mutationMode: mutable
    classification: internal
    fields:
      - {id: code, type: string, required: true, minLength: 1, maxLength: 64, classification: internal}
      - {id: label, type: string, required: true, maxLength: 200, classification: internal}
      - {id: group, type: reference, target: record-group, classification: internal}
      - {id: status, type: vocabulary-code, vocabulary: record-status, classification: internal}
    constraints:
      - {id: record-code-unique, kind: unique, fields: [code]}
    # An index lets a list filtered or sorted by its leading field skip the
    # rows that do not match. `check` reports a finding for a filterable or
    # sortable field no index leads with. The unique constraint above already
    # indexes `code`, and the compiler indexes every reference such as `group`.
    indexes:
      - {id: record-status, fields: [status]}
    # A selector profile names an exact-match question a caller may ask by
    # value, rather than a filter over a listing. Every field it names must
    # refuse the empty value, which is why `code` declares `minLength: 1` above.
    # `bregctl generate evidence-source` exports one Evidence source per
    # selector an access profile grants a lookup on.
    selectorProfiles:
      - {id: by-code, fields: [code]}

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
    permissions:
      - entity: record-group
        rowBoundaries: []
        operations: [create, get, list]
        readableFields: [code, label]
        writableFields: [code, label]
        filterableFields: [code]
      - entity: record
        rowBoundaries: []
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
    permissions:
      - entity: record
        operations: [get, list]
        readableFields: [code, label, group, status]
        filterableFields: [code]
        rowBoundaries:
          - {field: status, claim: registry_record_status, operator: equals}

  # A lookup-only source. It answers one exact-match question, by `code`, and
  # reads only the fields that answer it. `valueOrigin: request` says the caller
  # supplies the selector value. The profile grants no `list`, so it can confirm
  # a record whose code it is given and cannot enumerate the registry.
  # `bregctl generate evidence-source .` exports this grant as an Evidence
  # source definition, so a project written by `init` exports unmodified.
  #
  # `check` reports `access.profile.unrestricted_rows` for this profile: any
  # record's code answers it, and the value a caller supplies is not
  # authorization. That is intended for a source that vouches for the whole
  # registry. Close it by giving the grant a `rowBoundaries` entry, the way
  # `record-reader` above does.
  - id: evidence-source
    principalClaim: registry_principal
    requiredScopes: [registry:evidence:lookup]
    requiredPurposes: [evidence-source-read]
    permissions:
      - entity: record
        rowBoundaries: []
        operations: [lookup]
        readableFields: [code, status]
        lookups:
          - {selector: by-code, valueOrigin: request}

# Modules contribute to the model from their own files under `modules/`.
# `bregctl project lock` writes the version and content digest below;
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
# Raise `version` and re-run `bregctl project lock` after every edit
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
apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig

# Where the server listens. Client addresses and TLS termination belong to
# whatever sits in front of it: the runtime reads neither peer addresses nor
# forwarded headers.
listener:
  bind: 127.0.0.1:8080

# The environment, instance, and database this file serves. A package names
# none of them, so the same package directory is applied in every environment;
# `bregctl apply` records this identity in the database it activates.
identity:
  environment: local
  instanceId: generic-registry-1
  databaseId: generic-registry-db-1
  databaseInitializationEnvironment: local

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

# The activated package directory. The server starts only when the database
# records this package's digest, the `packageDigest` `bregctl package` reports,
# as its active package.
package:
  root: /replace/me/packages/build-1/package

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

# The key that derives the keyed references in audit entries and the secret
# that signs pagination cursors. Losing the audit key breaks the link between
# references written before and after it; losing the cursor secret invalidates
# issued cursors, so generate them once and keep them. The server appends audit
# entries to the absolute JSON Lines file `path`, in an owner-only directory;
# `bregctl` maintenance commands append to the sibling `audit.bregctl.jsonl`.
audit:
  hashKeyRef: secret:file/audit-key
  destination: file
  path: /var/lib/breg/audit/audit.jsonl
cursor:
  secretRef: secret:file/cursor-key

# One binding for every webhook destination the package's events declare, and
# no others: activation refuses a missing binding and an extra one alike. This
# project declares no event, so the map is empty. A destination's URL, shared
# HMAC key, and retry ceilings live only here, never in the project.
eventDestinations: {}
"#;

const INIT_DEV_CLIENTS: &[u8] =
    br#"# Local callers for `bregctl dev`. The owned ThunderID issuer that
# `dev` starts beside the registry, registers each client below and issues it
# short-lived tokens carrying these claims. One client binds each access profile
# that `tests/journeys.yaml` uses, with the claims those journeys expect, so a
# first start runs the journeys and serves the package without another file.
# A maintained refusal step can name the exact client for its profile with
# `testBindings`; the 'Explicit teaching clients' section of
# products/breg/DEV.md documents the closed binding format.
# `dev` generates a fresh private key per client under `.breg/dev/credentials/`;
# nothing here is a credential, and none of it belongs in a deployment.
version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: reader
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
  - id: source
    accessProfiles: [evidence-source]
    scopes: [registry:evidence:lookup]
    claims:
      registry_principal: generic-registry-source
      registry_purpose: evidence-source-read
"#;

const INIT_JOURNEYS: &[u8] = br#"# Project journeys: the requests `bregctl test` replays over real
# HTTP, with real credentials, against a throwaway database before a package is
# built. Every entity, profile, field, and claim below is resolved against the
# compiled project first, so a journey can never reach past what a profile
# already allows. The claims below are synthetic; credentials never belong here,
# `bregctl test` binds one per step from its own credentials file.
apiVersion: registry.registrystack.org/breg-journeys/v1
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
        ("dev-clients.yaml".to_owned(), INIT_DEV_CLIENTS.to_vec()),
    ])
}

/// The media type an initialized project's file is reported with.
fn init_media_type(path: &str) -> &'static str {
    if path.ends_with(".md") {
        "text/markdown"
    } else if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".txt") {
        "text/plain"
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
        if let Some(patched) = module_lock_patch::patch_module_locks(original, locks) {
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
    let write_failed = || {
        diagnostic(
            "module.lock.write_failed",
            "registry.yaml",
            "the project module locks could not be written",
        )
    };
    // Resolve once, then reread, stage, and rename through that descriptor, so
    // the file whose bytes are compared is the file that is replaced.
    let destination = SafeEntry::resolve(&project_path.join("registry.yaml")).map_err(|error| {
        path_diagnostic(
            error,
            "module.lock.write_failed",
            "registry.yaml",
            "the project directory is not available",
            "the project directory must be a directory and must not be a symbolic link",
        )
    })?;
    let current = read_bounded_source_entry(
        &destination,
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
    let parent = destination.parent();
    let temporary = OsString::from(format!(
        ".bregctl-lock-{}-{}.tmp",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let write_result = (|| {
        let mut file = parent
            .create_new(&temporary, 0o666)
            .map_err(|_| write_failed())?;
        file.write_all(updated).map_err(|_| write_failed())?;
        file.sync_all().map_err(|_| write_failed())?;
        destination
            .replace_from(&temporary)
            .map_err(|_| write_failed())
    })();
    if write_result.is_err() {
        let _ = parent.remove_file(&temporary);
    }
    write_result
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
            ArtifactSelector::EvidenceSource => false,
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
        .filter(|entity| entity.change_request.is_some())
        .map(|entity| {
            let request = entity.change_request.as_ref().expect("filtered request entity");
            let artifact = compiled.artifacts()
                .get(&format!("generated/schemas/{}.schema.json", entity.id))
                .expect("compiled entities have generated schemas");
            let schema: Value = serde_json::from_slice(&artifact.bytes)?;
            Ok(json!({
                "requestEntity": entity.id,
                "requestRoute": entity.route,
                "fields": entity.stored_fields.iter().map(|field| json!({
                    "field": field.logical.id,
                    "apiName": field.logical.api_name,
                    "schema": schema["properties"][&field.logical.api_name],
                })).collect::<Vec<_>>(),
                "contractFingerprint": request.contract_fingerprint,
                "bounds": {
                    "maximumTargets": request.maximum_targets,
                    "maximumFieldMutations": request.maximum_field_mutations,
                    "maximumSnapshotBytes": request.maximum_snapshot_bytes,
                },
                "planner": explain_change_request_planner(compiled, entity, request),
                "review": match &request.review {
                    registry_breg::model::CompiledChangeRequestReview::Required(requirement) => json!({
                        "authority": requirement.authority,
                        "policyId": requirement.policy_id,
                    }),
                    registry_breg::model::CompiledChangeRequestReview::None(no_review) => json!({
                        "mode": no_review.mode,
                    }),
                },
                "onApproved": request.on_approved,
                "application": request.application,
                "effects": request.effects.iter().map(|effect| {
                    let target = compiled.entities().get(&effect.target.entity_id);
                    json!({
                        "id": effect.id,
                        "operation": operation_wire_name(effect.operation),
                        "target": {
                            "entity": effect.target.entity_id,
                            "binding": match &effect.target.binding {
                                registry_breg::model::CompiledChangeRequestTargetBinding::Existing { from_field } => {
                                    json!({"kind": "existing", "fromField": field_summary(entity, from_field)})
                                }
                                registry_breg::model::CompiledChangeRequestTargetBinding::ReservedCreate { effect } => {
                                    json!({"kind": "reserved_create", "effect": effect})
                                }
                            },
                        },
                        "fields": effect.mutations.iter().map(|mutation| match mutation {
                            registry_breg::model::CompiledChangeRequestMutation::Set { field, value } => json!({
                                "kind": "set",
                                "target": field_summary_optional(target, field),
                                "value": match value {
                                    registry_breg::model::CompiledChangeRequestValue::FromField { field } => {
                                        json!({"kind": "from_field", "field": field_summary(entity, field)})
                                    }
                                    registry_breg::model::CompiledChangeRequestValue::FromEffect { effect, target_entity_id } => {
                                        json!({"kind": "from_effect", "effect": effect, "targetEntity": target_entity_id})
                                    }
                                },
                            }),
                            registry_breg::model::CompiledChangeRequestMutation::Clear { field } => json!({
                                "kind": "clear",
                                "target": field_summary_optional(target, field),
                            }),
                        }).collect::<Vec<_>>(),
                        "dependsOn": effect.depends_on.iter().collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
                "actions": request.actions.iter().map(|action| json!({
                    "operation": operation_wire_name(action.operation.access_operation()),
                    "routeId": compiled.routes().routes.iter()
                        .find(|route| route.entity_id == entity.id
                            && route.operation == action.operation.access_operation())
                        .map(|route| route.id.as_str()),
                    "method": "POST",
                    "preconditions": request_action_preconditions(action.operation.access_operation()),
                })).collect::<Vec<_>>(),
                "applyPermissions": request.apply_permissions.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "targetEntity": grant.target_entity_id,
                    "rowBoundaries": grant.row_boundaries,
                })).collect::<Vec<_>>(),
                "presencePermissions": request.presence_permissions.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "targetEntity": grant.target_entity_id,
                    "requestRowBoundaries": grant.request_row_boundaries,
                })).collect::<Vec<_>>(),
            }))
        })
        .collect::<serde_json::Result<Vec<_>>>()?;
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
                "directWriteRestriction": "controlled operations are absent from ordinary permissions and require compiled apply_request context",
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
    request_entity: &registry_breg::model::CompiledEntity,
    request: &registry_breg::model::CompiledChangeRequest,
) -> Value {
    let Some(planner) = request.planner.as_ref() else {
        return json!({
            "kind": "declarative",
            "abi": registry_breg::contract::CHANGE_REQUEST_PLAN_ABI_V1,
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

fn explain_routes(compiled: &CompiledRegistry) -> serde_json::Result<Value> {
    // The explain payload mixes two record shapes in one array (entity routes and
    // action routes, which share no field), so every record needs an explicit `kind`
    // discriminator. It is distinct from `actionRouteKind`, which says which action
    // route a record is rather than which shape it has. The field lives here, not on
    // `CompiledRoute` or `CompiledActionRoute`: both are `deny_unknown_fields` types
    // that round-trip through package inventories, and `CompiledActionRoute` is also
    // byte-compared as the generated `compiled/actions.json`.
    let mut value = serde_json::to_value(compiled.routes())?;
    let routes = value
        .get_mut("routes")
        .and_then(Value::as_array_mut)
        .expect("compiled routes serialize with a routes array");
    for route in routes.iter_mut() {
        route
            .as_object_mut()
            .expect("compiled routes serialize as objects")
            .insert("kind".to_string(), Value::from("entity"));
    }
    routes.extend(compiled.actions().routes.iter().map(|route| {
        json!({
            "kind": "action",
            "id": route.id,
            "actionId": route.action_id,
            "actionRouteKind": action_route_kind_wire_name(route.kind),
            "method": route.method,
            "path": route.path,
            "operation": operation_wire_name(route.operation),
            "accessProfiles": route.access_profiles,
            "defaultAccessProfile": route.default_access_profile,
            "requiresIdempotencyKey": route.kind == registry_breg::model::ActionRouteKind::Invoke,
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
                        "requiresIdempotencyKey": route.kind == registry_breg::model::ActionRouteKind::Invoke,
                    })
                })
                .collect::<Vec<_>>();
            let mut summary = json!({
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
                            registry_breg::model::CompiledActionMutation::Set { field, value } => json!({
                                "kind": "set",
                                "target": field_summary_optional(target_entity, field),
                                "value": match value {
                                    registry_breg::model::CompiledActionValue::Literal { .. } => json!({"kind": "computed"}),
                                    registry_breg::model::CompiledActionValue::FromInput { input } => {
                                        json!({"kind": "from_input", "input": action_input_identity(action, input)})
                                    }
                                    registry_breg::model::CompiledActionValue::FromEffect { effect, target_entity_id } => {
                                        json!({"kind": "from_effect", "effect": effect, "targetEntity": target_entity_id})
                                    }
                                },
                            }),
                            registry_breg::model::CompiledActionMutation::Clear { field } => json!({
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
                    "source": action_target_use_source(action, &target.source),
                    "conditionRequired": target.condition_required,
                })).collect::<Vec<_>>(),
                "requiredConditionKeys": action.target_uses.iter()
                    .filter(|target| target.condition_required)
                    .filter_map(|target| match &target.source {
                        registry_breg::model::CompiledActionTargetUseSource::Input { input } => {
                            action.inputs.iter().find(|candidate| candidate.id == *input)
                        }
                        registry_breg::model::CompiledActionTargetUseSource::Effect { .. } => None,
                    })
                    .map(|input| input.api_name.as_str())
                    .collect::<BTreeSet<_>>(),
                "permissions": action.permissions.iter().map(|grant| json!({
                    "profile": grant.profile_id,
                    "default": grant.default,
                    "anonymous": grant.anonymous,
                    "requiredScopes": grant.required_scopes,
                    "requiredPurposes": grant.required_purposes,
                    "operations": grant.operations.iter().map(|operation| operation_wire_name(*operation)).collect::<Vec<_>>(),
                    "targets": grant.targets.iter().map(|target| json!({
                        "entity": target.entity_id,
                        "operation": target.operation.map(operation_wire_name),
                        "source": target.source.as_ref().map(|source| action_target_use_source(action, source)),
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
            });
            if let Some(handler) = &action.handler {
                use registry_breg::model::CompiledActionHandlerKind;
                // The summary names the compiled backend and its source
                // fingerprint; the Rhai-only members stay Rhai-only.
                let (kind, backend_source) = match handler.kind {
                    CompiledActionHandlerKind::Rhai => (
                        json!("rhai"),
                        json!({
                            "scriptSha256": handler.script_sha256,
                            "rhaiVersion": handler.rhai_version,
                            "limits": handler.limits,
                        }),
                    ),
                    CompiledActionHandlerKind::Wasm => (
                        json!("wasm"),
                        json!({
                            "moduleSha256": handler.module_sha256,
                            // The preflight compatibility contract for a WASM
                            // handler: which servers run it and where package
                            // loading is refused before activation.
                            "compatibility": {
                                "minimumServer": "registry-breg built with the wasm feature",
                                "serversBeforeWasmSupport":
                                    "refuse the package at load with a typed handler error and no state change",
                                "serversBuiltWithoutTheFeature":
                                    "refuse the package during load because handler rederivation requires WASM support",
                                "moduleSha256": handler.module_sha256,
                            },
                        }),
                    ),
                };
                let mut handler_summary = json!({
                    "kind": kind, "abi": handler.abi,
                    "entrypoint": "handle", "context": "ctx.inputs", "inputKeys": "authored_ids",
                    "possibleWrites": handler.writes,
                    "refusals": handler.refusals.iter().map(|(code,label)| json!({"code":code,"label":label})).collect::<Vec<_>>(),
                    "outcomes": ["effects", "refusal"],
                    "omittedSlots": "no_write_or_result; all_declared_existing_targets_still_require_admission_and_conditions",
                    "evaluation": "after_locked_receipt_recovery_before_target_locks",
                    "reads": "supplied_inputs_only",
                    "replay": "recover_committed_result_without_handler_evaluation",
                });
                if let Some(object) = handler_summary.as_object_mut() {
                    object.extend(backend_source.as_object().cloned().unwrap_or_default());
                }
                summary["handler"] = handler_summary;
            }
            if action.handler.as_ref().is_some_and(|handler| handler.abi == registry_breg::contract::ACTION_HANDLER_ABI_V2) {
                summary["evidence"] = json!({
                    "capabilities": action.evidence,
                    "maximumCalls": action.evidence.len(),
                    "maximumCallsPerCapability": 1,
                    "maximumConcurrentEvaluations": 8,
                    "maximumRetainedBytes": 1_048_576,
                    "maximumResponseBytes": 262_144,
                    "retentionSeconds": 86_400,
                    "maximumAssertionLifetimeSeconds": 300,
                    "clockSkewSeconds": 0,
                    "maximumObservationAgeSeconds": 300,
                    "defaultActionDeadlineMilliseconds": 10_000,
                    "deadline": "bounded_by_operator_http_request_timeout_and_action_timeout",
                    "invocation": "optional_explicit_helper_calls; omission_makes_no_remote_request",
                    "disclosure": "remote_requirement_disclosure_is_not_reduced_by_output_selection",
                    "lifecycle": "outside_postgres; frozen_transcript_reused_for_sql_retries; receipt_replay_has_zero_calls"
                });
                summary["handler"]["evaluation"] = json!("outside_postgres_after_admission_and_receipt_preflight");
            }
            if !action.requires.is_empty() {
                summary["requires"] = json!(action.requires.iter().map(|requirement| {
                    json!({
                        "input": action_input_identity(action, &requirement.input),
                        "entity": requirement.entity_id,
                        "field": field_summary_optional(
                            compiled.entities().get(&requirement.entity_id),
                            &requirement.field,
                        ),
                        "equals": requirement.equals,
                        "evaluated": "before_effects_under_target_lock",
                    })
                }).collect::<Vec<_>>());
            }
            summary
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
                    "maxTop": registry_breg::query::MAX_TOP,
                    "maxSelectedFields": registry_breg::query::MAX_SELECTED_FIELDS,
                    "maxFilterPayloadBytes": registry_breg::query::MAX_QUERY_PAYLOAD_BYTES,
                    "maxFilterDepth": registry_breg::query::MAX_FILTER_DEPTH,
                    "maxFilterNodes": registry_breg::query::MAX_FILTER_NODES,
                    "maxFilterPredicates": registry_breg::query::MAX_FILTER_PREDICATES,
                    "maxInValues": registry_breg::query::MAX_IN_VALUES,
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
    entity: &'a registry_breg::model::CompiledEntity,
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

fn field_summary(entity: &registry_breg::model::CompiledEntity, field_id: &str) -> Value {
    field_summary_optional(Some(entity), field_id)
}

fn field_summary_optional(
    entity: Option<&registry_breg::model::CompiledEntity>,
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
    entity: &'a registry_breg::model::CompiledEntity,
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

fn action_input_summary(input: &registry_breg::model::CompiledActionInput) -> Value {
    json!({
        "input": input.id,
        "apiName": input.api_name,
        "fieldType": input.field_type,
        "required": input.required,
        "classification": input.classification,
    })
}

fn action_input_identity(action: &registry_breg::model::CompiledAction, input_id: &str) -> Value {
    action
        .inputs
        .iter()
        .find(|input| input.id == input_id)
        .map(action_input_summary)
        .unwrap_or_else(|| json!({"input": input_id}))
}

fn action_target_use_source(
    action: &registry_breg::model::CompiledAction,
    source: &registry_breg::model::CompiledActionTargetUseSource,
) -> Value {
    match source {
        registry_breg::model::CompiledActionTargetUseSource::Effect { effect } => {
            json!({"kind": "effect", "effect": effect})
        }
        registry_breg::model::CompiledActionTargetUseSource::Input { input } => {
            json!({"kind": "input", "input": action_input_identity(action, input)})
        }
    }
}

fn action_target_summary(effect: &registry_breg::model::CompiledActionEffect) -> Value {
    match &effect.target.binding {
        registry_breg::model::CompiledActionTargetBinding::Create => json!({
            "entity": effect.target.entity_id,
            "binding": {"kind": "create"},
        }),
        registry_breg::model::CompiledActionTargetBinding::Existing { input } => json!({
            "entity": effect.target.entity_id,
            "binding": {
                "kind": "existing",
                "input": input,
            },
        }),
    }
}

fn action_route_kind_wire_name(kind: registry_breg::model::ActionRouteKind) -> &'static str {
    match kind {
        registry_breg::model::ActionRouteKind::Invoke => "invoke",
        registry_breg::model::ActionRouteKind::TargetConditions => "target_conditions",
    }
}

fn request_action_preconditions(
    operation: registry_breg::contract::Operation,
) -> Vec<&'static str> {
    let mut preconditions = vec!["Idempotency-Key", "If-Match"];
    if matches!(operation, registry_breg::contract::Operation::ApplyRequest) {
        preconditions.push("proposalVersion");
        preconditions.push("effectDigest");
    }
    preconditions
}

fn operation_wire_name(operation: registry_breg::contract::Operation) -> &'static str {
    match operation {
        registry_breg::contract::Operation::Create => "create",
        registry_breg::contract::Operation::Get => "get",
        registry_breg::contract::Operation::Lookup => "lookup",
        registry_breg::contract::Operation::List => "list",
        registry_breg::contract::Operation::Patch => "patch",
        registry_breg::contract::Operation::Tombstone => "tombstone",
        registry_breg::contract::Operation::Batch => "batch",
        registry_breg::contract::Operation::Revisions => "revisions",
        registry_breg::contract::Operation::SubmitRequest => "submit_request",
        registry_breg::contract::Operation::ReviseRequest => "revise_request",
        registry_breg::contract::Operation::CancelRequest => "cancel_request",
        registry_breg::contract::Operation::ApplyRequest => "apply_request",
        registry_breg::contract::Operation::Invoke => "invoke",
        registry_breg::contract::Operation::Snapshot => "snapshot",
        registry_breg::contract::Operation::Import => "import",
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
    operators: &[registry_breg::model::CompiledQueryFilterOperator],
) -> Vec<&'static str> {
    let mut wire = BTreeSet::new();
    for operator in operators {
        match operator {
            registry_breg::model::CompiledQueryFilterOperator::Equals => {
                wire.insert("eq");
                wire.insert("ne");
            }
            registry_breg::model::CompiledQueryFilterOperator::In => {
                wire.insert("in");
            }
            registry_breg::model::CompiledQueryFilterOperator::Range => {
                wire.insert("ge");
                wire.insert("gt");
                wire.insert("le");
                wire.insert("lt");
            }
            registry_breg::model::CompiledQueryFilterOperator::IsNull => {
                wire.insert("eq null");
            }
            registry_breg::model::CompiledQueryFilterOperator::IsNotNull => {
                wire.insert("ne null");
            }
            registry_breg::model::CompiledQueryFilterOperator::Prefix => {
                wire.insert("startswith");
            }
            registry_breg::model::CompiledQueryFilterOperator::Contains => {
                wire.insert("contains");
            }
        }
    }
    wire.into_iter().collect()
}

fn filter_examples(
    api_name: &str,
    field_type: &FieldTypeSource,
    operators: &[registry_breg::model::CompiledQueryFilterOperator],
) -> Vec<String> {
    operators
        .iter()
        .filter_map(|operator| filter_example(api_name, field_type, *operator))
        .collect()
}

fn filter_example(
    api_name: &str,
    field_type: &FieldTypeSource,
    operator: registry_breg::model::CompiledQueryFilterOperator,
) -> Option<String> {
    match operator {
        registry_breg::model::CompiledQueryFilterOperator::Equals => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter={api_name} eq {first}"))
        }
        registry_breg::model::CompiledQueryFilterOperator::In => {
            let first = filter_literal(field_type)?;
            let second = alternate_filter_literal(field_type)?;
            Some(format!("$filter={api_name} in ({first},{second})"))
        }
        registry_breg::model::CompiledQueryFilterOperator::Range => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter={api_name} ge {first}"))
        }
        registry_breg::model::CompiledQueryFilterOperator::IsNull => {
            Some(format!("$filter={api_name} eq null"))
        }
        registry_breg::model::CompiledQueryFilterOperator::IsNotNull => {
            Some(format!("$filter={api_name} ne null"))
        }
        registry_breg::model::CompiledQueryFilterOperator::Prefix => {
            let first = filter_literal(field_type)?;
            Some(format!("$filter=startswith({api_name},{first})"))
        }
        registry_breg::model::CompiledQueryFilterOperator::Contains => {
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

/// Resolve the project directory to a held descriptor, refusing a symbolic link
/// at every component. Callers that read the project's own files afterwards read
/// them through the returned descriptor.
fn validate_project_directory(project_path: &Path) -> Result<SafeDir, Diagnostic> {
    if project_path.as_os_str().is_empty() || has_parent_component(project_path) {
        return Err(diagnostic(
            "source.project.path_unsafe",
            "project",
            "the project path must not contain parent-directory components",
        ));
    }
    validate_directory(project_path, "source.project.invalid")
}

/// Resolve a directory to a held descriptor, refusing a symbolic link at every
/// component. The descriptor is what callers must use afterwards, so replacing
/// a component of `path` after this returns cannot redirect their work.
fn validate_directory(path: &Path, code: &str) -> Result<SafeDir, Diagnostic> {
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
) -> Result<SafeDir, Diagnostic> {
    SafeDir::resolve(path).map_err(|error| {
        path_diagnostic(
            error,
            code,
            report_path,
            unavailable_message,
            invalid_message,
        )
    })
}

/// Translate a path-resolution refusal into the caller's diagnostic vocabulary.
/// A platform with no kernel-enforced symbolic-link-free resolution reports its
/// own code, because the path itself was never the problem there.
fn path_diagnostic(
    error: SafePathError,
    code: &str,
    report_path: &str,
    unavailable_message: &str,
    invalid_message: &str,
) -> Diagnostic {
    match error {
        SafePathError::Unsupported => diagnostic(
            "path.no_symlink_unsupported",
            report_path,
            "this platform offers no kernel-enforced symbolic-link-free path resolution",
        ),
        SafePathError::NotFound | SafePathError::Unavailable => {
            diagnostic(code, report_path, unavailable_message)
        }
        SafePathError::Path | SafePathError::Symlink => {
            diagnostic(code, report_path, invalid_message)
        }
    }
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
    let entry = SafeEntry::resolve(path).map_err(|error| {
        path_diagnostic(
            error,
            missing_code,
            report_path,
            "the required authoring source is not available",
            "authoring sources must be regular files and must not be symbolic links",
        )
    })?;
    read_bounded_source_entry(&entry, missing_code, report_path, bound)
}

/// Read a bounded regular file through an already-resolved entry, for callers
/// that must reread the exact file they resolved rather than the path again.
fn read_bounded_source_entry(
    entry: &SafeEntry,
    missing_code: &str,
    report_path: &str,
    bound: u64,
) -> Result<Vec<u8>, Diagnostic> {
    read_bounded_source_entry_with_identity(entry, missing_code, report_path, bound)
        .map(|(bytes, _)| bytes)
}

/// Read a bounded regular file through an already-resolved entry and report the
/// identity of the descriptor the bytes came from, for callers that must record
/// which file they read instead of opening the name again to ask.
fn read_bounded_source_entry_with_identity(
    entry: &SafeEntry,
    missing_code: &str,
    report_path: &str,
    bound: u64,
) -> Result<(Vec<u8>, fs::Metadata), Diagnostic> {
    let invalid = || {
        diagnostic(
            "source.file.invalid",
            report_path,
            "authoring sources must be regular files and must not be symbolic links",
        )
    };
    let missing = || {
        diagnostic(
            missing_code,
            report_path,
            "the required authoring source is not available",
        )
    };
    let stat = entry.stat().map_err(|_| missing())?;
    if stat.is_symlink() || !stat.is_file() {
        return Err(invalid());
    }
    if stat.len() > bound {
        return Err(diagnostic(
            "source.file.bounds",
            report_path,
            "an authoring source exceeds its fixed size bound",
        ));
    }
    // The descriptor comes from the resolved parent with `O_NOFOLLOW`, so no
    // ancestor and no symbolic link can redirect the open. The final name is
    // still resolved a second time here, so the identity check below is what
    // rejects a name relinked between the stat above and this open.
    let file = entry.open_read().map_err(|_| {
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
    if !opened.is_file() {
        return Err(invalid());
    }
    ensure_source_entry_identity(stat, &opened, report_path)?;
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
    Ok((bytes, opened))
}

/// Refuse an authoring source whose opened descriptor is not the entry that was
/// stat'ed.
///
/// Stat and open are two calls on the same name. `O_NOFOLLOW` and a held parent
/// descriptor keep both of them inside the resolved directory, but a writer with
/// access to that directory can still relink the name to a different regular
/// file in between, and the bytes read would then belong to a file whose kind,
/// size, and content the caller never inspected. Device and inode identify the
/// file behind the descriptor, so comparing them refuses the substitution.
fn ensure_source_entry_identity(
    stat: EntryStat,
    opened: &fs::Metadata,
    report_path: &str,
) -> Result<(), Diagnostic> {
    if stat.is_same_file_as(opened) {
        return Ok(());
    }
    Err(diagnostic(
        "source.file.invalid",
        report_path,
        "an authoring source changed while it was being read",
    ))
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
    // Only the shape of the path is judged here. Whether the destination is
    // already taken is decided below, through the parent descriptor this
    // resolves, rather than by reaching the pathname a second time.
    if output.as_os_str().is_empty() || has_parent_component(output) || output.file_name().is_none()
    {
        return Err(diagnostic(
            "output.destination.invalid",
            "output",
            "the output directory must be a new path without parent-directory components",
        ));
    }
    let write_failed = || {
        diagnostic(
            "output.write.failed",
            "output",
            "a generated artifact could not be written",
        )
    };
    // Resolving once yields the parent directory descriptor that every stage,
    // write, cleanup, and publication below runs through, so replacing a
    // component of `output` afterwards cannot redirect any of them.
    let destination = SafeEntry::resolve(output).map_err(|error| {
        path_diagnostic(
            error,
            "output.parent.invalid",
            "output.parent",
            "the output parent directory is not available; create it, or give a destination inside a directory that exists",
            "the output parent must be a directory and must not be a symbolic link",
        )
    })?;
    let parent = destination.parent();
    if destination.exists().map_err(|_| {
        diagnostic(
            "output.destination.invalid",
            "output",
            "the output destination could not be inspected",
        )
    })? {
        return Err(diagnostic(
            "output.destination.invalid",
            "output",
            "the output directory must be a new path without parent-directory components",
        ));
    }

    let staged = create_staging_directory(parent)?;
    let result = (|| {
        let root = parent.open_directory(&staged).map_err(|_| write_failed())?;
        for (relative_path, bytes) in files {
            let (directory, name) = artifact_destination(&root, relative_path)?;
            // The staged tree keeps the process umask that the previous
            // pathname-based writer applied, so published output permissions
            // are unchanged.
            let mut file = directory
                .create_new(&name, 0o666)
                .map_err(|_| write_failed())?;
            file.write_all(bytes).map_err(|_| write_failed())?;
            file.sync_all().map_err(|_| write_failed())?;
        }
        before_publish(output)?;
        destination.publish_from(&staged).map_err(|_| {
            diagnostic(
                "output.publish.failed",
                "output",
                "the generated artifact directory could not be published",
            )
        })
    })();
    if result.is_err() {
        let _ = parent.remove_tree(&staged);
    }
    result
}

/// Create a uniquely named staging directory as a child of `parent` and return
/// its name, which stays valid relative to that descriptor.
fn create_staging_directory(parent: &SafeDir) -> Result<OsString, Diagnostic> {
    let stage_failed = || {
        diagnostic(
            "output.stage.failed",
            "output",
            "a staged output directory could not be created",
        )
    };
    for _ in 0..64 {
        let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let staged = OsString::from(format!(".bregctl-stage-{}-{counter}", std::process::id()));
        match parent.create_directory(&staged, 0o777) {
            Ok(()) => return Ok(staged),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(stage_failed()),
        }
    }
    Err(stage_failed())
}

/// Walk a compiler-supplied artifact path from the staged root descriptor,
/// creating each intermediate directory through the descriptor above it, and
/// return the directory that holds the artifact together with its file name.
fn artifact_destination(
    root: &SafeDir,
    artifact_path: &str,
) -> Result<(SafeDir, OsString), Diagnostic> {
    let unsafe_path = || {
        diagnostic(
            "artifact.path.invalid",
            "artifacts",
            "the compiler returned an unsafe artifact path",
        )
    };
    let path = Path::new(artifact_path);
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return Err(unsafe_path()),
        }
    }
    let name = names.pop().ok_or_else(unsafe_path)?.to_owned();
    // Create only what this tool can also take away. The staged tree is removed
    // by `SafeDir::remove_tree`, which walks at most `MAX_REMOVE_TREE_DEPTH`
    // levels below the staging directory, so a deeper artifact path would stage
    // a tree that neither the failure cleanup nor a later removal could reach.
    if names.len() >= MAX_REMOVE_TREE_DEPTH as usize {
        return Err(diagnostic(
            "artifact.path.invalid",
            "artifacts",
            "the compiler returned an artifact path deeper than this tool removes",
        ));
    }
    let mut directory = root.try_clone().map_err(|_| {
        diagnostic(
            "output.write.failed",
            "output",
            "a generated artifact could not be written",
        )
    })?;
    for part in names {
        directory = directory
            .open_or_create_directory(part, 0o777)
            .map_err(|_| {
                diagnostic(
                    "output.write.failed",
                    "output",
                    "a generated artifact could not be written",
                )
            })?;
    }
    Ok((directory, name))
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
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

/// Render the common report shape: one lead sentence, then aligned detail.
fn render_report(lead: &str, pairs: &[(&str, String)], stdout: &mut dyn Write) -> io::Result<()> {
    let mut lines = report::Lines::new();
    lines.lead(lead);
    lines.pairs(pairs);
    stdout.write_all(lines.finish().as_bytes())
}

/// Render the common report shape followed by the advisory findings a
/// successful command still reports.
fn render_report_with_findings(
    lead: &str,
    pairs: &[(&str, String)],
    diagnostics: &[Diagnostic],
    stdout: &mut dyn Write,
) -> io::Result<()> {
    let mut lines = report::Lines::new();
    lines.lead(lead);
    lines.pairs(pairs);
    let findings = diagnostics
        .iter()
        .map(|diagnostic| report::Finding {
            severity: match diagnostic.severity {
                DiagnosticSeverity::Error => report::Severity::Error,
                DiagnosticSeverity::Finding => report::Severity::Finding,
            },
            code: &diagnostic.code,
            path: &diagnostic.path,
            message: &diagnostic.message,
        })
        .collect::<Vec<_>>();
    lines.findings(&findings);
    stdout.write_all(lines.finish().as_bytes())
}

/// Map the CLI's diagnostic envelope onto the report renderer's findings, so
/// a refusal, a check, and a diff all present a diagnostic the same way.
fn report_findings(diagnostics: &[ToolDiagnostic]) -> Vec<report::Finding<'_>> {
    diagnostics
        .iter()
        .map(|diagnostic| report::Finding {
            severity: match diagnostic.severity {
                DiagnosticSeverity::Error => report::Severity::Error,
                DiagnosticSeverity::Finding => report::Severity::Finding,
            },
            code: &diagnostic.code,
            path: &diagnostic.path,
            message: &diagnostic.message,
        })
        .collect()
}

/// Render a list of values as one detail value, naming an empty list rather
/// than leaving the reader an empty column to interpret.
fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

/// The sentence that opens a success report: what the command did, and the
/// counts a reader would otherwise have to total up from the lines below.
fn success_lead(report: &SuccessReport) -> String {
    let artifacts = report.artifacts.len();
    match report.command {
        "init" => format!(
            "Initialized a registry project. {} written.",
            report::counted(artifacts, "artifact")
        ),
        "check" if report.package_digest.is_some() => "Package verified.".to_owned(),
        "check" => match report.profile {
            ProfileArg::Authoring => "Authoring check passed.".to_owned(),
            ProfileArg::Production => "Production check passed.".to_owned(),
        },
        // A lock that already held writes nothing, and a count of zero
        // artifacts would read as a write that produced no file.
        "project lock" if artifacts == 0 => "Locked the project modules.".to_owned(),
        "project lock" => format!(
            "Locked the project modules. {} written.",
            report::counted(artifacts, "artifact")
        ),
        "generate" => format!("Generated {}.", report::counted(artifacts, "artifact")),
        consent_module::COMMAND => format!(
            "Added the consent module. {} written.",
            report::counted(artifacts, "artifact")
        ),
        // `explain lifecycle` is the one explain that compiles nothing, and
        // the absent revision is how the report says so.
        "explain" if report.revision.is_none() => {
            "Explained the engine's request lifecycle. No project was compiled.".to_owned()
        }
        "explain" => "Explained the compiled inventory.".to_owned(),
        other => format!("{other} succeeded."),
    }
}

fn render_success(report: &SuccessReport, stdout: &mut dyn Write) -> io::Result<()> {
    let mut lines = report::Lines::new();
    lines.lead(&success_lead(report));
    if let Some(revision) = &report.revision {
        lines.pairs(&[("revision", revision.clone())]);
    }
    if let Some(digest) = &report.package_digest {
        lines.pairs(&[("package digest", digest.clone())]);
    }

    if !report.artifacts.is_empty() {
        lines.blank();
        for artifact in &report.artifacts {
            lines.bullet(&artifact.path);
        }
    }

    lines.findings(&report_findings(&report.findings));

    // An access explanation and a consent module explanation are each folded
    // into the report. Any other explanation is a document this renderer has
    // no shape for, so it keeps its own JSON rendering below the report.
    let mut document = None;
    if let Some(explanation) = &report.explanation {
        if explanation.get("scopeMatching").is_some()
            || explanation.get("mode").and_then(Value::as_str) == Some("offline_synthetic")
        {
            push_access_explanation(explanation, &mut lines);
        } else if explanation.get("requireConsent").is_some() {
            push_consent_module_explanation(explanation, &mut lines);
        } else {
            document = Some(serde_json::to_string_pretty(explanation).map_err(io::Error::other)?);
        }
    }

    lines.steps(&report.next_steps);
    stdout.write_all(lines.finish().as_bytes())?;
    if let Some(document) = document {
        writeln!(stdout)?;
        writeln!(stdout, "{document}")?;
    }
    Ok(())
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
        render_success(report, stdout)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
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
        let script = report
            .handler
            .as_ref()
            .map(|identity| {
                (
                    "handler kind",
                    "handler ABI",
                    "handler script SHA-256",
                    identity,
                )
            })
            .or_else(|| {
                report.planner.as_ref().map(|identity| {
                    (
                        "planner kind",
                        "planner ABI",
                        "planner script SHA-256",
                        identity,
                    )
                })
            });
        script
            .ok_or_else(|| io::Error::other("missing compiled script identity"))
            .and_then(|(kind_label, abi_label, digest_label, identity)| {
                let mut lines = report::Lines::new();
                if report.planner.is_some() {
                    lines.lead(&format!(
                        "Ran the planner. Produced {}.",
                        report::counted(report.effects.len(), "effect")
                    ));
                } else if report.refusal.is_some() {
                    lines.lead("Ran the handler. Returned a declared refusal.");
                } else {
                    lines.lead(&format!(
                        "Ran the handler. Returned {}.",
                        report::counted(report.effects.len(), "effect")
                    ));
                }
                let mut pairs = vec![("compiled revision", report.compiled_revision.clone())];
                match &report.action {
                    Some(action) => pairs.push(("action", action.clone())),
                    None => pairs.push(("request entity", report.request_entity.clone())),
                }
                pairs.extend([
                    (kind_label, identity.kind.to_owned()),
                    (abi_label, identity.abi.clone()),
                    (digest_label, identity.script_sha256.clone()),
                ]);
                if report.assertions_passed == Some(true) {
                    pairs.push(("exact assertions", "passed".to_owned()));
                }
                if let Some(refusal) = &report.refusal {
                    pairs.push((
                        "refusal",
                        format!(
                            "{} ({})",
                            refusal["code"].as_str().unwrap_or(""),
                            refusal["label"].as_str().unwrap_or("")
                        ),
                    ));
                    if let Some(field) = refusal.get("field").and_then(Value::as_str) {
                        pairs.push(("refusal input", field.to_owned()));
                    }
                }
                pairs.push(("effects", report.counts.effects.to_string()));
                pairs.push(("field mutations", report.counts.field_mutations.to_string()));
                pairs.push(("dependencies", report.counts.dependencies.to_string()));
                lines.pairs(&pairs);

                // One block per effect, so the fields and dependencies an effect
                // carries are named once instead of on every effect line.
                for effect in &report.effects {
                    lines.blank();
                    lines.item(&format!("effect {}", effect.id));
                    lines.pairs_at(
                        2,
                        &[
                            ("target", effect.target_kind.to_owned()),
                            ("operation", effect.operation.to_owned()),
                            ("fields", list_or_none(&effect.fields)),
                            ("dependencies", list_or_none(&effect.depends_on)),
                        ],
                    );
                }
                stdout.write_all(lines.finish().as_bytes())
            })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn push_access_explanation(explanation: &Value, lines: &mut report::Lines) {
    if explanation.get("mode").and_then(Value::as_str) == Some("offline_synthetic") {
        let admitted = explanation["admitted"].as_bool() == Some(true);
        lines.verdict(
            "Synthetic profile admission:",
            if admitted { "allowed" } else { "refused" },
            admitted,
        );
        let mut pairs = vec![(
            "reason",
            explanation["reason"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned(),
        )];
        if let Some(recipients) = explanation["recipients"]
            .as_array()
            .filter(|recipients| !recipients.is_empty())
        {
            pairs.push(("recipients", joined_strings(recipients)));
        }
        lines.pairs(&pairs);
        lines.blank();
        lines.prose(
            1,
            "No credentials verified, records checked, or authority issued. Claim values are not printed.",
        );
        if explanation["effectiveProfile"].is_object() {
            lines.blank();
            push_access_profile(&explanation["effectiveProfile"], 1, lines);
        }
        return;
    }
    lines.heading("Access:");
    for key in [
        "scopeMatching",
        "purposeMatching",
        "rowMatching",
        "profileSelection",
    ] {
        let sentence = explanation[key].as_str().unwrap_or("");
        if !sentence.is_empty() {
            lines.listed(1, sentence);
        }
    }
    if let Some(entities) = explanation["entities"].as_array() {
        for entity in entities {
            lines.blank();
            lines.item_at(
                1,
                &format!(
                    "entity {} ({})",
                    entity["entity"].as_str().unwrap_or(""),
                    entity["classification"].as_str().unwrap_or("")
                ),
            );
            if !entity["requirements"].is_null() {
                lines.pairs_at(
                    2,
                    &[("mandatory requirements", entity["requirements"].to_string())],
                );
            }
            if let Some(profiles) = entity["profiles"].as_array() {
                for profile in profiles {
                    lines.blank();
                    push_access_profile(profile, 2, lines);
                }
            }
        }
    }
    if explanation["consent"].is_object() {
        lines.blank();
        push_consent_explanation(&explanation["consent"], lines);
    }
}

/// The `module add consent` explanation: what the generated module holds, the
/// vocabularies it added versus reused, the `requireConsent` line each gated
/// entity still needs, and whether the project compiles yet.
fn push_consent_module_explanation(explanation: &Value, lines: &mut report::Lines) {
    lines.heading("Consent module:");
    lines.pairs(&[
        (
            "subject",
            explanation["subject"].as_str().unwrap_or("").to_owned(),
        ),
        (
            "module",
            explanation["module"].as_str().unwrap_or("").to_owned(),
        ),
    ]);
    lines.blank();
    lines.pairs(&[
        ("entities", joined_or(&explanation["entities"], "none")),
        ("actions", joined_or(&explanation["actions"], "none")),
        (
            "access profiles",
            joined_or(&explanation["accessProfiles"], "none"),
        ),
    ]);
    let vocabularies = &explanation["vocabularies"];
    lines.blank();
    lines.pairs(&[
        (
            "vocabularies added",
            joined_or(&vocabularies["added"], "none"),
        ),
        (
            "vocabularies reused",
            joined_or(&vocabularies["reused"], "none"),
        ),
    ]);
    if let Some(requirements) = explanation["requireConsent"]
        .as_array()
        .filter(|requirements| !requirements.is_empty())
    {
        lines.blank();
        lines.item("requireConsent lines to add:");
        for requirement in requirements {
            lines.pairs_at(
                2,
                &[(
                    requirement["entity"].as_str().unwrap_or(""),
                    requirement["line"].as_str().unwrap_or("").to_owned(),
                )],
            );
        }
    }
    let compiles = explanation["compiles"].as_bool() == Some(true);
    lines.verdict(
        "Compiles:",
        if compiles { "yes" } else { "not yet" },
        compiles,
    );
}

fn joined_strings(values: &[Value]) -> String {
    values
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn joined_or(values: &Value, empty: &str) -> String {
    match values.as_array() {
        Some(values) if !values.is_empty() => joined_strings(values),
        _ => empty.to_owned(),
    }
}

fn consent_issuers(issuers: &Value) -> String {
    let rendered = issuers
        .as_array()
        .into_iter()
        .flatten()
        .map(|issuer| {
            format!(
                "{} ({})",
                issuer["action"].as_str().unwrap_or(""),
                issuer["issuer"].as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>();
    if rendered.is_empty() {
        "none".to_owned()
    } else {
        rendered.join(", ")
    }
}

fn consent_client(client: &Value) -> (String, String) {
    (
        format!("client {}", client["client"].as_str().unwrap_or("")),
        format!(
            "{}: {}",
            client["organization"].as_str().unwrap_or("unmapped"),
            joined_or(&client["recipients"], "none, consent fails closed")
        ),
    )
}

fn push_consent_explanation(consent: &Value, lines: &mut report::Lines) {
    lines.heading("Consent:");
    for key in ["condition", "unmappedClients", "trustModel", "ungating"] {
        let sentence = consent[key].as_str().unwrap_or("");
        if !sentence.is_empty() {
            lines.listed(1, sentence);
        }
    }
    for permission in consent["permissions"].as_array().into_iter().flatten() {
        lines.blank();
        lines.item_at(
            1,
            &format!(
                "permission {} over {}",
                permission["profile"].as_str().unwrap_or(""),
                permission["entity"].as_str().unwrap_or("")
            ),
        );
        lines.prose(2, permission["condition"].as_str().unwrap_or(""));
        let readable = permission["readableFields"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|field| {
                format!(
                    "{} ({})",
                    field["field"].as_str().unwrap_or(""),
                    field["classification"].as_str().unwrap_or("unclassified")
                )
            })
            .collect::<Vec<_>>();
        lines.pairs_at(
            2,
            &[
                (
                    "record",
                    permission["record"].as_str().unwrap_or("").to_owned(),
                ),
                ("on", permission["on"].as_str().unwrap_or("").to_owned()),
                (
                    "scope",
                    permission["scope"].as_str().unwrap_or("").to_owned(),
                ),
                (
                    "purposes",
                    joined_or(&permission["purposes"], "unrestricted"),
                ),
                (
                    "max duration",
                    permission["maxDuration"].as_str().unwrap_or("").to_owned(),
                ),
                (
                    "probe function",
                    permission["probeFunction"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                ),
                ("indexes", joined_or(&permission["indexes"], "none")),
                (
                    "readable fields",
                    if readable.is_empty() {
                        "none".to_owned()
                    } else {
                        readable.join(", ")
                    },
                ),
                (
                    "issuing actions",
                    consent_issuers(&permission["issuingActions"]),
                ),
            ],
        );
        let clients = permission["clients"]
            .as_array()
            .into_iter()
            .flatten()
            .map(consent_client)
            .collect::<Vec<_>>();
        let clients = clients
            .iter()
            .map(|(label, value)| (label.as_str(), value.clone()))
            .collect::<Vec<_>>();
        lines.pairs_at(2, &clients);
    }
    lines.blank();
    lines.item_at(1, "recipients");
    let mut pairs = Vec::new();
    for organization in consent["organizations"].as_array().into_iter().flatten() {
        let retired = organization["retired"].as_bool() == Some(true);
        pairs.push((
            format!("organization {}", organization["id"].as_str().unwrap_or("")),
            if retired {
                "retired, no client acts for it".to_owned()
            } else {
                joined_or(&organization["clients"], "none")
            },
        ));
    }
    for group in consent["groups"].as_array().into_iter().flatten() {
        pairs.push((
            format!("group {}", group["id"].as_str().unwrap_or("")),
            format!(
                "{}: {}",
                joined_or(&group["members"], "no members"),
                joined_or(&group["clients"], "no clients")
            ),
        ));
    }
    for client in consent["clients"].as_array().into_iter().flatten() {
        pairs.push(consent_client(client));
    }
    pairs.push((
        "consent issuers".to_owned(),
        consent_issuers(&consent["issuers"]),
    ));
    let pairs = pairs
        .iter()
        .map(|(label, value)| (label.as_str(), value.clone()))
        .collect::<Vec<_>>();
    lines.pairs_at(2, &pairs);
}

fn push_access_profile(profile: &Value, depth: usize, lines: &mut report::Lines) {
    lines.item_at(
        depth,
        &format!("profile {}", profile["id"].as_str().unwrap_or("")),
    );
    let mut fields = vec![(
        "principal claim",
        profile["principalClaim"]
            .as_str()
            .unwrap_or("none (anonymous)")
            .to_owned(),
    )];
    let membership_restricted = profile["membershipBoundaries"]
        .as_array()
        .is_some_and(|boundaries| !boundaries.is_empty());
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
        let rendered = if value.is_null() || value.as_array().is_some_and(Vec::is_empty) {
            if field == "rowBoundaries" && membership_restricted {
                "governed membership required".to_owned()
            } else {
                empty.to_owned()
            }
        } else {
            value.to_string()
        };
        fields.push((label, rendered));
    }
    if membership_restricted {
        fields.push((
            "membership restrictions (all)",
            profile["membershipBoundaries"].to_string(),
        ));
    }
    if profile["requireConsent"]
        .as_array()
        .is_some_and(|requirements| !requirements.is_empty())
    {
        fields.push((
            "consent required (all)",
            profile["requireConsent"].to_string(),
        ));
    }
    for field in [
        "anonymous",
        "allowCount",
        "revisionAccess",
        "allowDataExport",
    ] {
        fields.push((field, profile[field].as_bool().unwrap_or(false).to_string()));
    }
    lines.pairs_at(depth + 1, &fields);
}

fn write_examples_success(
    report: &Value,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    if format == OutputFormat::Json {
        let result = serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout));
        return write_result(result, stderr);
    }
    let mut lines = report::Lines::new();
    lines.lead(&format!(
        "bregctl {} succeeded.",
        report["command"].as_str().unwrap_or("examples")
    ));
    let fields = ["project", "scenario", "attempt"]
        .into_iter()
        .filter_map(|key| report[key].as_str().map(|v| (key, v.to_owned())))
        .collect::<Vec<_>>();
    lines.pairs(&fields);
    for scenario in report["scenarios"].as_array().into_iter().flatten() {
        lines.blank();
        lines.item(scenario["id"].as_str().unwrap_or_default());
        lines.prose(2, scenario["description"].as_str().unwrap_or_default());
        lines.pairs_at(
            2,
            &[(
                "input",
                scenario["input"].as_str().unwrap_or_default().to_owned(),
            )],
        );
        for step in scenario["steps"].as_array().into_iter().flatten() {
            lines.prose(
                2,
                &format!(
                    "{}: {} {} as {}/{}",
                    step["id"].as_str().unwrap_or_default(),
                    step["operation"].as_str().unwrap_or_default(),
                    step["entity"].as_str().unwrap_or_default(),
                    step["client"].as_str().unwrap_or_default(),
                    step["accessProfile"].as_str().unwrap_or_default()
                ),
            );
        }
    }
    for attempt in report["attempts"].as_array().into_iter().flatten() {
        lines.blank();
        lines.item(&format!(
            "{} attempt {}",
            attempt["scenario"].as_str().unwrap_or_default(),
            attempt["attempt"].as_str().unwrap_or_default()
        ));
        if let Some(step) = attempt["pendingStep"].as_str() {
            lines.prose(
                2,
                &format!("Pending original step: {step}. Resume this attempt."),
            );
        }
    }
    if let Some(message) = report["message"].as_str() {
        lines.blank();
        lines.prose(0, message);
    }
    if let Some(captures) = report["captures"].as_object() {
        for (alias, capture) in captures {
            lines.pairs(&[(
                alias.as_str(),
                format!(
                    "{} ({})",
                    capture["id"].as_str().unwrap_or_default(),
                    capture["entity"].as_str().unwrap_or_default()
                ),
            )]);
        }
    }
    if let Some(results) = report.get("results") {
        lines.blank();
        lines.item("Observed results");
        // JSON encoding escapes user-authored control characters and preserves
        // the actual native record/history shapes for the teaching exercise.
        lines.raw(serde_json::to_string_pretty(results).unwrap_or_default());
    }
    if let Some(next) = report["nextCommand"].as_str() {
        lines.blank();
        lines.pairs(&[("next command", next.to_owned())]);
    }
    write_result(stdout.write_all(lines.finish().as_bytes()), stderr)
}

fn write_dev_success(
    report: &Value,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        {
            let mut lines = report::Lines::new();
            lines.lead(&format!(
                "bregctl {} succeeded.",
                report["command"].as_str().unwrap_or("dev")
            ));
            let pairs: Vec<(&str, String)> = [
                ("status", "status"),
                ("client", "client"),
                ("access profiles", "accessProfilesText"),
                ("client id file", "clientIdFile"),
                ("assertion key file", "assertionKeyFile"),
                ("project", "project"),
                ("breg url", "bregUrl"),
                ("token endpoint", "tokenEndpoint"),
                ("audience", "audience"),
                ("package digest", "packageDigest"),
                ("state file", "stateFile"),
                ("runtime config", "runtimeConfig"),
                ("webhook receiver", "webhookUrl"),
                ("events file", "eventsFile"),
            ]
            .into_iter()
            .filter_map(|(label, field)| {
                report[field]
                    .as_str()
                    .map(|value| (label, value.to_owned()))
            })
            .collect();
            lines.pairs(&pairs);
            if let Some(deliveries) = report["deliveries"].as_array() {
                lines.blank();
                lines.item(&format!(
                    "{} received.",
                    report::counted(deliveries.len(), "delivery")
                ));
                for delivery in deliveries {
                    lines.blank();
                    let pairs: Vec<(&str, String)> = [
                        ("event id", "eventId"),
                        ("event", "eventType"),
                        ("entity", "entity"),
                        ("trigger", "trigger"),
                        ("delivery", "deliveryId"),
                        ("destination", "destinationId"),
                        ("status", "status"),
                        ("generation", "generation"),
                        ("attempt", "attempt"),
                    ]
                    .into_iter()
                    .filter_map(|(label, field)| {
                        delivery.get(field).map(|value| {
                            (
                                label,
                                value
                                    .as_str()
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| value.to_string()),
                            )
                        })
                    })
                    .collect();
                    lines.pairs_at(2, &pairs);
                    if let Some(payload) = delivery.get("payload") {
                        lines.pairs_at(2, &[("payload", payload.to_string())]);
                    }
                }
            }
            // Credential file references, never credential bytes.
            let clients = report["clients"].as_array().into_iter().flatten();
            for client in clients {
                lines.blank();
                lines.item(&format!(
                    "client {}",
                    client["id"].as_str().unwrap_or_default()
                ));
                let files: Vec<(&str, String)> = [
                    ("client id file", "clientIdFile"),
                    ("assertion key file", "assertionKeyFile"),
                ]
                .into_iter()
                .filter_map(|(label, field)| {
                    client[field].as_str().map(|path| (label, path.to_owned()))
                })
                .collect();
                lines.pairs_at(2, &files);
            }
            stdout.write_all(lines.finish().as_bytes())
        }
    };
    write_result(result, stderr)
}

fn write_doctor_success(
    advisories: &[registry_breg::postgres::BaselineAdvisory],
    role_mode: registry_breg::postgres::RoleMode,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let report = DoctorSuccessReport {
        ok: true,
        command: "doctor",
        checked: &doctor::CHECKED_DEPENDENCIES,
        role_mode: role_mode.as_str(),
        advisories: advisories
            .iter()
            .map(|advisory| DoctorAdvisory {
                code: advisory.code(),
                severity: advisory.severity().as_str(),
                message: advisory.message(),
                observed: ObservedNumbers(advisory.observed()),
            })
            .collect(),
    };
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, &report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        {
            let mut lines = report::Lines::new();
            lines.lead(&format!(
                "{} passed.",
                report::counted(report.checked.len(), "dependency check")
            ));
            let mut pairs: Vec<(&str, String)> = report
                .checked
                .iter()
                .map(|dependency| (*dependency, "pass".to_owned()))
                .collect();
            pairs.push(("roleMode", report.role_mode.to_owned()));
            lines.pairs(&pairs);
            if role_mode == registry_breg::postgres::RoleMode::Single {
                lines.prose(2, SINGLE_ROLE_MODE_NOTE);
            }
            if !report.advisories.is_empty() {
                lines.heading("PostgreSQL advisories:");
                for advisory in &report.advisories {
                    lines.item(&format!("{}  {}", advisory.severity, advisory.code));
                    lines.prose(2, advisory.message);
                    let observed: Vec<(&str, String)> = advisory
                        .observed
                        .0
                        .iter()
                        .map(|(name, value)| (*name, value.to_string()))
                        .collect();
                    lines.pairs_at(2, &observed);
                }
            }
            stdout.write_all(lines.finish().as_bytes())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_field_encryption_keygen_success(
    outcome: &field_encryption::KeygenOutcome,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let report = FieldEncryptionKeygenSuccessReport {
        ok: true,
        command: "field-encryption keygen",
        output: &outcome.output.display().to_string(),
    };
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, &report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        render_report(
            "Wrote one base64 field data key.",
            &[("output", report.output.to_owned())],
            stdout,
        )
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_field_encryption_preflight_success(
    report: &FieldEncryptionPreflightSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        {
            let mut lines = report::Lines::new();
            let covered: u64 = report
                .outcome
                .report
                .steps
                .iter()
                .flat_map(|step| step.fields.iter().map(|field| field.plaintext_row_count))
                .sum();
            lines.lead(&format!(
                "Preflighted the field-encryption backfill. {} to seal.",
                report::counted_total(covered, "plaintext value")
            ));
            let mut pairs = vec![(
                "package digest".to_owned(),
                report.outcome.package_digest.clone(),
            )];
            for step in &report.outcome.report.steps {
                let choice = match step.history_choice {
                    registry_breg::migration_plan::ReviewedFieldEncryptionHistory::EraseAndRebaseline => {
                        "erase-and-rebaseline"
                    }
                    registry_breg::migration_plan::ReviewedFieldEncryptionHistory::RetainPlaintextHistory => {
                        "retain-plaintext-history"
                    }
                };
                pairs.push((format!("entity {}", step.entity_id), choice.to_owned()));
                for field in &step.fields {
                    pairs.push((
                        format!("entity {} field {}", step.entity_id, field.api_name),
                        format!(
                            "{} plaintext, {} journal, {} request targets, {} proposals, {} cached \
                             responses, {} outbox payloads",
                            field.plaintext_row_count,
                            field.journal_row_count,
                            field.request_target_row_count,
                            field.request_proposal_row_count,
                            field.idempotency_row_count,
                            field.outbox_row_count
                        ),
                    ));
                }
            }
            let borrowed = pairs
                .iter()
                .map(|(label, value)| (label.as_str(), value.clone()))
                .collect::<Vec<_>>();
            lines.pairs(&borrowed);
            stdout.write_all(lines.finish().as_bytes())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

fn write_field_encryption_erase_history_success(
    report: &FieldEncryptionEraseHistorySuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        render_report(
            &format!(
                "Erased the flip's retained plaintext history. {} covered again.",
                report::counted_total(
                    report.outcome.outcome.rebaseline.verified_record_count,
                    "record"
                )
            ),
            &[
                ("package digest", report.outcome.package_digest.clone()),
                (
                    "erased records",
                    report.outcome.outcome.erased_record_count.to_string(),
                ),
                (
                    "erased revisions",
                    report.outcome.outcome.erased_revision_count.to_string(),
                ),
                (
                    "erased commit members",
                    report
                        .outcome
                        .outcome
                        .erased_commit_member_count
                        .to_string(),
                ),
                (
                    "scrubbed change contexts",
                    report
                        .outcome
                        .outcome
                        .scrubbed_change_context_count
                        .to_string(),
                ),
                (
                    "scrubbed outbox payloads",
                    report
                        .outcome
                        .outcome
                        .scrubbed_outbox_payload_count
                        .to_string(),
                ),
                (
                    "scrubbed cached responses",
                    report
                        .outcome
                        .outcome
                        .scrubbed_cached_response_count
                        .to_string(),
                ),
                (
                    "scrubbed request targets",
                    report
                        .outcome
                        .outcome
                        .scrubbed_request_target_count
                        .to_string(),
                ),
                (
                    "scrubbed request proposals",
                    report
                        .outcome
                        .outcome
                        .scrubbed_request_proposal_count
                        .to_string(),
                ),
                (
                    "coverage baseline position",
                    report
                        .outcome
                        .outcome
                        .rebaseline
                        .baseline_position
                        .to_string(),
                ),
                (
                    "verified records",
                    report
                        .outcome
                        .outcome
                        .rebaseline
                        .verified_record_count
                        .to_string(),
                ),
            ],
            stdout,
        )
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
            ExitCode::from(OPERATIONAL_FAILURE_EXIT)
        }
    }
}

/// One key-generation refusal. Every message is value free: the operator
/// already named the output path on the command line, and the key material
/// itself never exists in a message.
fn field_encryption_keygen_failure(error: field_encryption::KeygenError) -> FailureReport {
    let diagnostic = match error {
        field_encryption::KeygenError::RelativeOutput => diagnostic(
            "field_encryption.keygen.path_invalid",
            "--output",
            "the data-key output path must be absolute",
        ),
        field_encryption::KeygenError::OutputExists => diagnostic(
            "field_encryption.keygen.output_exists",
            "--output",
            "refusing to overwrite an existing data-key file; choose a new output path",
        ),
        field_encryption::KeygenError::RandomSource => diagnostic(
            "field_encryption.keygen.random_source_unavailable",
            "--output",
            "the random source refused to yield a data key",
        ),
        field_encryption::KeygenError::Write => diagnostic(
            "field_encryption.keygen.write_refused",
            "--output",
            "the data-key file could not be written with owner-only permissions",
        ),
    };
    FailureReport {
        ok: false,
        command: "field-encryption keygen",
        diagnostics: vec![tool_diagnostic(
            diagnostic,
            DiagnosticArtifact::CommandArguments,
            SuggestedAction::ChooseSafeOutputDirectory,
        )],
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
        render_report(
            "Verified the package against the runtime it is bound to.",
            &[
                ("assurance", "runtime_bound".to_owned()),
                ("package digest", report.package_digest.clone()),
                ("registry id", report.registry.id.clone()),
                ("registry version", report.registry.version.clone()),
                ("registry revision", report.registry.revision.clone()),
                ("modules", report.inventory.modules.to_string()),
                ("entities", report.inventory.entities.to_string()),
                ("routes", report.inventory.routes.to_string()),
                (
                    "access entries",
                    report.inventory.access_entries.to_string(),
                ),
                ("queries", report.inventory.queries.to_string()),
                (
                    "event deliveries",
                    report.inventory.event_deliveries.to_string(),
                ),
                (
                    "DDL statements",
                    report.inventory.ddl_statements.to_string(),
                ),
                (
                    "generated artifacts",
                    report.inventory.generated_artifacts.to_string(),
                ),
            ],
            stdout,
        )
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
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
        let mut fields = vec![
            ("profile", "production".to_owned()),
            ("package digest", report.package_digest.clone()),
            ("registry revision", report.registry_revision.clone()),
            ("package files", report.package_files.to_string()),
        ];
        if let Some(revision) = &report.revision {
            fields.push(("revision", revision.clone()));
        }
        render_report(
            "Sealed and published a deployment package.",
            &fields,
            stdout,
        )
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
        render_report_with_findings(
            &format!(
                "Fixture run passed. {}.",
                report::counted(report.successful_journey_ids.len(), "journey")
            ),
            &[
                ("profile", "production".to_owned()),
                ("registry revision", report.registry_revision.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
                (
                    "successful journeys",
                    list_or_none(&report.successful_journey_ids),
                ),
                ("receipt sha256", report.receipt.sha256.clone()),
                ("receipt bytes", report.receipt.byte_length.to_string()),
            ],
            &report.diagnostics,
            stdout,
        )
    };
    write_result(result, stderr)
}

fn write_schema_fingerprint(
    report: &SchemaFingerprintReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        render_report(
            "Measured the schema a fresh install of the candidate produces. No fixtures ran and no receipt was written.",
            &[
                ("profile", "production".to_owned()),
                ("registry revision", report.registry_revision.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
            ],
            stdout,
        )
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
        render_report(
            match report.activation {
                ApplyActivation::Initial => "Activated the first package on this registry.",
                ApplyActivation::Successor => "Activated the package over its predecessor.",
                ApplyActivation::RoleChange => {
                    "Activated the active package again with the configured database roles."
                }
            },
            &[
                (
                    "activation",
                    match report.activation {
                        ApplyActivation::Initial => "initial",
                        ApplyActivation::Successor => "successor",
                        ApplyActivation::RoleChange => "role_change",
                    }
                    .to_owned(),
                ),
                ("package digest", report.package_digest.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
                ("activation id", report.activation_id.clone()),
            ],
            stdout,
        )
    };
    write_result(result, stderr)
}

fn write_plan_success(
    report: &PlanSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let lead = match report.activation {
            PlanActivation::Initial => "Planned the first activation on this registry; nothing was changed. Run `bregctl apply --initial --package DIR` to activate it.",
            PlanActivation::Successor => "Planned a successor activation over the active package; nothing was changed. Run `bregctl apply --package DIR` to activate it.",
            PlanActivation::RoleChange => "Planned activating the active package again with the configured database roles; nothing was changed. Run `bregctl apply --package DIR` to activate it.",
            PlanActivation::None => "The database already runs this package with the configured database roles; there is nothing to apply.",
        };
        let mut lines = report::Lines::new();
        lines.lead(lead);
        let mut pairs = vec![
            (
                "activation",
                match report.activation {
                    PlanActivation::Initial => "initial",
                    PlanActivation::Successor => "successor",
                    PlanActivation::RoleChange => "role_change",
                    PlanActivation::None => "none",
                }
                .to_owned(),
            ),
            ("package digest", report.package_digest.clone()),
            ("registry revision", report.registry_revision.clone()),
        ];
        if let Some(active) = &report.active_package_digest {
            pairs.push(("active package digest", active.clone()));
        }
        pairs.push(("role mode", report.role_mode.to_owned()));
        if let Some(resumed) = &report.resumes_activation_id {
            pairs.push(("resumes activation", resumed.clone()));
        }
        pairs.push((
            "plan kind",
            plan_kind_name(report.migration.plan_kind()).to_owned(),
        ));
        pairs.push(("change count", report.migration.change_count().to_string()));
        pairs.push((
            "reviewed migration count",
            report.migration.reviewed_migrations().len().to_string(),
        ));
        pairs.push(("checks passed", report.checks.join(", ")));
        lines.pairs(&pairs);
        if !report.required_backups.is_empty() {
            lines.blank();
            lines.item("apply requires --backup for");
            for binding in &report.required_backups {
                lines.item_at(1, binding);
            }
        }
        stdout.write_all(lines.finish().as_bytes())
    };
    write_result(result, stderr)
}

fn write_status_success(
    report: &StatusSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let lead = if report.maintenance_status == "ready" {
            "The database runs its active package and is ready.".to_owned()
        } else {
            format!(
                "The database is in maintenance: an activation it pinned is {}. Retry the same `bregctl apply --package DIR`, or assess it with `bregctl migration reconcile`.",
                report.maintenance_status
            )
        };
        let mut lines = report::Lines::new();
        lines.lead(&lead);
        let mut pairs = vec![
            ("package id", report.package_id.clone()),
            ("database id", report.database_id.clone()),
            (
                "active package digest",
                report.active_package_digest.clone(),
            ),
            ("activation id", report.activation_id.clone()),
        ];
        if let Some(revision) = &report.registry_revision {
            pairs.push(("registry revision", revision.clone()));
        }
        if let Some(role_mode) = &report.role_mode {
            pairs.push(("role mode", role_mode.clone()));
        }
        pairs.push(("schema fingerprint", report.schema_fingerprint.clone()));
        pairs.push(("maintenance status", report.maintenance_status.clone()));
        if let Some(target) = &report.maintenance_target_package_digest {
            pairs.push(("maintenance target", target.clone()));
        }
        lines.pairs(&pairs);
        for entry in &report.ledger {
            lines.blank();
            lines.item(&format!("activation {}", entry.apply_order));
            let mut fields = vec![
                ("activation id", entry.activation_id.clone()),
                ("package digest", entry.package_digest.clone()),
                ("registry revision", entry.registry_revision.clone()),
                ("plan kind", entry.plan_kind.clone()),
                ("migration kind", entry.migration_kind.clone()),
                ("outcome", entry.outcome.clone()),
                ("role mode", entry.role_mode.clone()),
                ("started at", entry.started_at.clone()),
            ];
            if let Some(applied) = &entry.applied_at {
                fields.push(("applied at", applied.clone()));
            }
            lines.pairs_at(1, &fields);
        }
        stdout.write_all(lines.finish().as_bytes())
    };
    write_result(result, stderr)
}

fn write_result(result: io::Result<()>, stderr: &mut dyn Write) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
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
            let _ = writeln!(stderr, "bregctl: output could not be written");
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
    render_report(
        &format!(
            "Reconciled the migration. Outcome {}, {}.",
            outcome.outcome,
            report::counted(outcome.migration_step_count, "step")
        ),
        &[
            ("outcome", outcome.outcome.to_string()),
            ("executed", outcome.executed.to_string()),
            (
                "maintenance status",
                optional(outcome.maintenance_status.as_deref()).to_owned(),
            ),
            (
                "pinned target digest",
                optional(outcome.maintenance_target_package_digest.as_deref()).to_owned(),
            ),
            (
                "active package digest",
                optional(outcome.active_package_digest.as_deref()).to_owned(),
            ),
            (
                "presented target digest",
                outcome.target_package_digest.to_string(),
            ),
            (
                "target catalog finding",
                optional(outcome.target_catalog_finding).to_owned(),
            ),
            (
                "active catalog finding",
                optional(outcome.active_catalog_finding).to_owned(),
            ),
            (
                "unresolvable reason",
                optional(outcome.unresolvable_reason).to_owned(),
            ),
            ("plan kind", outcome.plan_kind.to_string()),
            ("migration steps", outcome.migration_step_count.to_string()),
            (
                "reviewed plan closed",
                optional_flag(outcome.reviewed_plan_closed).to_owned(),
            ),
            (
                "durable step progress",
                optional_flag(outcome.durable_step_progress).to_owned(),
            ),
        ],
        stdout,
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
        render_report(
            &format!(
                "Erased the requested history. {} affected.",
                report::counted_total(report.outcome.affected_commit_count, "commit")
            ),
            &[
                ("package revision", report.outcome.package_revision.clone()),
                ("coverage ready", report.outcome.coverage_ready.to_string()),
                (
                    "unavailable after position",
                    match report.outcome.unavailable_after_position {
                        Some(position) => position.to_string(),
                        None => "none".to_owned(),
                    },
                ),
                (
                    "affected commits",
                    report.outcome.affected_commit_count.to_string(),
                ),
                (
                    "erased revisions",
                    report.outcome.erased_revision_count.to_string(),
                ),
                (
                    "erased commit members",
                    report.outcome.erased_commit_member_count.to_string(),
                ),
                (
                    "scrubbed change contexts",
                    report.outcome.scrubbed_change_context_count.to_string(),
                ),
                (
                    "scrubbed outbox payloads",
                    report.outcome.scrubbed_outbox_payload_count.to_string(),
                ),
                (
                    "scrubbed cached responses",
                    report.outcome.scrubbed_cached_response_count.to_string(),
                ),
                (
                    "scrubbed request targets",
                    report.outcome.scrubbed_request_target_count.to_string(),
                ),
                (
                    "scrubbed request proposals",
                    report.outcome.scrubbed_request_proposal_count.to_string(),
                ),
                (
                    "removed descriptors",
                    report.outcome.removed_descriptor_count.to_string(),
                ),
            ],
            stdout,
        )
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
        {
            let mut lines = report::Lines::new();
            lines.lead(&format!(
                "Rebaselined the history. {} verified.",
                report::counted_total(report.outcome.verified_record_count, "record")
            ));
            lines.pairs(&[
                ("package revision", report.outcome.package_revision.clone()),
                (
                    "coverage baseline position",
                    report.outcome.baseline_position.to_string(),
                ),
                (
                    "verified entities",
                    report.outcome.verified_entity_count.to_string(),
                ),
                (
                    "verified records",
                    report.outcome.verified_record_count.to_string(),
                ),
                (
                    "previous coverage baseline position",
                    report
                        .outcome
                        .previous_coverage_baseline_position
                        .to_string(),
                ),
                (
                    "previous unavailable after position",
                    match report.outcome.previous_unavailable_after_position {
                        Some(position) => position.to_string(),
                        None => "none".to_owned(),
                    },
                ),
            ]);
            // A statement about what the rebaselined history no longer holds,
            // not something the reader does next.
            lines.blank();
            lines.prose(
                1,
                "Snapshot references before the new baseline remain unavailable.",
            );
            stdout.write_all(lines.finish().as_bytes())
        }
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
        render_report(
            &format!(
                "Validated the input. {} in {}.",
                report::counted_total(report.item_count, "item"),
                report::counted(report.chunk_count, "chunk")
            ),
            &[
                ("package revision", report.package_revision.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
                ("entity", report.entity_id.clone()),
                ("profile", report.profile_id.clone()),
                (
                    "operation",
                    data_operation_name(report.operation).to_owned(),
                ),
                ("input bytes", report.input_length.to_string()),
                ("input sha256", report.input_digest.clone()),
                ("items", report.item_count.to_string()),
                ("chunks", report.chunk_count.to_string()),
                ("maximum items", report.maximum_items.to_string()),
                ("maximum bytes", report.maximum_bytes.to_string()),
            ],
            stdout,
        )
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
        render_report(
            &format!(
                "Imported the input. {} committed{}.",
                report::counted_total(report.committed_items, "item"),
                if report.complete {
                    ""
                } else {
                    ", and the import is not complete"
                }
            ),
            &[
                ("package revision", report.package_revision.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
                ("entity", report.entity_id.clone()),
                ("profile", report.profile_id.clone()),
                (
                    "operation",
                    data_operation_name(report.operation).to_owned(),
                ),
                ("ingestion run", report.run_id.clone()),
                ("input bytes", report.input_length.to_string()),
                ("items", report.item_count.to_string()),
                ("completed chunks", report.completed_chunk_count.to_string()),
                ("committed items", report.committed_items.to_string()),
                ("complete", report.complete.to_string()),
            ],
            stdout,
        )
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
        render_report(
            &format!(
                "Exported the records. {}{}.",
                report::counted_total(report.record_count, "record"),
                if report.complete {
                    ""
                } else {
                    ", and the export is not complete"
                }
            ),
            &[
                ("package revision", report.package_revision.clone()),
                ("schema fingerprint", report.schema_fingerprint.clone()),
                ("entity", report.entity_id.clone()),
                ("profile", report.profile_id.clone()),
                ("fields", list_or_none(&report.requested_fields)),
                ("completed pages", report.completed_page_count.to_string()),
                ("records", report.record_count.to_string()),
                ("output bytes", report.output_length.to_string()),
                ("complete", report.complete.to_string()),
            ],
            stdout,
        )
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
        render_report(
            "Built the sample delivery. The canonical request follows.",
            &[("event", report.outcome.event_id.clone())],
            stdout,
        )
        // The request is the artifact the reader signs and compares, so it is
        // quoted byte for byte rather than folded into the report above it.
        .and_then(|()| writeln!(stdout))
        .and_then(|()| {
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
        report
            .outcome
            .deliveries
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<String>, _>>()
            .map_err(io::Error::other)
            .and_then(|deliveries| {
                let mut lines = report::Lines::new();
                lines.lead(&format!(
                    "Listed the webhook deliveries. {}.",
                    report::counted(deliveries.len(), "delivery")
                ));
                if !deliveries.is_empty() {
                    lines.blank();
                    for delivery in &deliveries {
                        lines.bullet(delivery);
                    }
                }
                stdout.write_all(lines.finish().as_bytes())
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
        render_report(
            "Queued the delivery for replay.",
            &[
                ("event id", report.outcome.event_id.clone()),
                ("delivery id", report.outcome.delivery_id.clone()),
                ("generation", report.outcome.generation.to_string()),
            ],
            stdout,
        )
    };
    write_result(result, stderr)
}

fn write_webhook_discard_success(
    report: &WebhookDiscardSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        render_report(
            "Discarded the delivery. It cannot be replayed.",
            &[
                ("event id", report.outcome.event_id.clone()),
                ("delivery id", report.outcome.delivery_id.clone()),
                ("generation", report.outcome.generation.to_string()),
            ],
            stdout,
        )
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
        report
            .outcome
            .page
            .requests
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<String>, _>>()
            .map_err(io::Error::other)
            .and_then(|requests| {
                let mut lines = report::Lines::new();
                lines.lead(&format!(
                    "Listed the retained requests. {}.",
                    report::counted(requests.len(), "request")
                ));
                if let Some(cursor) = &report.outcome.page.next_cursor {
                    lines.pairs(&[("next cursor", cursor.clone())]);
                }
                if !requests.is_empty() {
                    lines.blank();
                    for request in &requests {
                        lines.bullet(request);
                    }
                }
                stdout.write_all(lines.finish().as_bytes())
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
        {
            let dry_run = &report.outcome.dry_run;
            serde_json::to_string(&dry_run.erasure)
                .map_err(io::Error::other)
                .and_then(|erasure| {
                    render_report(
                        &format!(
                    "Previewed the erasure. The request is {} for erasure. Nothing was erased.",
                    if dry_run.eligible_for_erasure {
                        "eligible"
                    } else {
                        "not eligible"
                    }
                ),
                        &[
                            ("request entity", dry_run.request_entity_id.clone()),
                            ("request id", dry_run.request_id.clone()),
                            ("proposal version", dry_run.proposal_version.to_string()),
                            ("retention mode", dry_run.retention_mode.to_owned()),
                            ("pinned", dry_run.pinned.to_string()),
                            (
                                "eligible for erasure",
                                dry_run.eligible_for_erasure.to_string(),
                            ),
                            ("erasure", erasure),
                        ],
                        stdout,
                    )
                })
        }
    };
    write_result(result, stderr)
}

fn write_attachment_cleanup_success(
    report: &AttachmentCleanupSuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        render_report(
            "Retried unreferenced attachment cleanup.",
            &[
                (
                    "pending external deletions",
                    report.outcome.pending_external_deletions.to_string(),
                ),
                (
                    "external deletion tombstones",
                    report.outcome.external_deletion_tombstones.to_string(),
                ),
            ],
            stdout,
        )
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
        {
            let erase = &report.outcome.erase;
            serde_json::to_string(&erase.erasure)
                .map_err(io::Error::other)
                .and_then(|erasure| {
                    render_report(
                        "Erased the retained request.",
                        &[
                            ("request entity", erase.request_entity_id.clone()),
                            ("request id", erase.request_id.clone()),
                            ("proposal version", erase.proposal_version.to_string()),
                            ("retention mode", erase.retention_mode.to_owned()),
                            ("erased", erasure),
                        ],
                        stdout,
                    )
                })
        }
    };
    write_result(result, stderr)
}

fn write_review_recovery_success(
    report: &ReviewRecoverySuccessReport,
    format: OutputFormat,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let result = if format == OutputFormat::Json {
        serde_json::to_writer_pretty(&mut *stdout, report)
            .map_err(io::Error::other)
            .and_then(|()| writeln!(stdout))
    } else {
        let recovery = &report.outcome.recovery;
        render_report(
            match recovery.state {
                "pending" => "Queued the review for resubmission.",
                "queued" => "Queued the approved application for retry.",
                _ => "Closed the review.",
            },
            &[
                ("request entity", recovery.request_entity_id.clone()),
                ("request id", recovery.request_id.clone()),
                ("proposal version", recovery.proposal_version.to_string()),
                ("authority", recovery.authority.clone()),
                ("previous state", recovery.previous_state.clone()),
                (
                    "previous code",
                    recovery
                        .previous_code
                        .clone()
                        .unwrap_or_else(|| "none".to_owned()),
                ),
                ("state", recovery.state.to_owned()),
                ("code", recovery.code.unwrap_or("none").to_owned()),
            ],
            stdout,
        )
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
    let mut lines = report::Lines::new();
    lines.lead(&format!(
        "Explained the migration plan. {}, {}.",
        report::counted(plan.change_count(), "change"),
        report::counted(plan.reviewed_migrations().len(), "reviewed migration")
    ));
    lines.pairs(&[
        ("assurance", "runtime_bound".to_owned()),
        ("package digest", report.package_digest.clone()),
        ("plan kind", plan_kind_name(plan.plan_kind()).to_owned()),
        ("has predecessor", plan.has_predecessor().to_string()),
        ("has prior baseline", plan.has_prior_baseline().to_string()),
        ("change count", plan.change_count().to_string()),
        (
            "compatible additive changes",
            counts.compatible_additive().to_string(),
        ),
        (
            "data backfill required changes",
            counts.data_backfill_required().to_string(),
        ),
        (
            "access or disclosure changes",
            counts.access_or_disclosure_change().to_string(),
        ),
        (
            "destructive or irreversible changes",
            counts.destructive_or_irreversible().to_string(),
        ),
        ("unsupported changes", counts.unsupported().to_string()),
        (
            "generated statement count",
            plan.generated_statement_count().to_string(),
        ),
        (
            "reviewed migration count",
            plan.reviewed_migrations().len().to_string(),
        ),
    ]);

    // Each reviewed migration is a group of its own, so its fields are named
    // once at the head instead of on every line beneath it.
    for (index, migration) in plan.reviewed_migrations().iter().enumerate() {
        lines.blank();
        lines.item(&format!("reviewed migration {}", index + 1));
        let mut fields = vec![
            (
                "change class",
                change_class_name(migration.change_class()).to_owned(),
            ),
            ("recovery", recovery_name(migration.recovery()).to_owned()),
            ("lock timeout ms", migration.lock_timeout_ms().to_string()),
            (
                "statement timeout ms",
                migration.statement_timeout_ms().to_string(),
            ),
            (
                "transactional step count",
                migration.transactional_step_count().to_string(),
            ),
            (
                "chunked step count",
                migration.chunked_step_count().to_string(),
            ),
            (
                "pre-assertion count",
                migration.pre_assertion_count().to_string(),
            ),
            (
                "post-assertion count",
                migration.post_assertion_count().to_string(),
            ),
            ("backup required", migration.backup_required().to_string()),
        ];
        if let Some(bounds) = migration.chunked_step_bounds() {
            fields.push((
                "minimum chunk size",
                bounds.minimum_chunk_size().to_string(),
            ));
            fields.push((
                "maximum chunk size",
                bounds.maximum_chunk_size().to_string(),
            ));
            fields.push((
                "maximum total rows",
                bounds.maximum_total_rows().to_string(),
            ));
        }
        lines.pairs_at(2, &fields);
    }
    stdout.write_all(lines.finish().as_bytes())
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
        report
            .diff
            .changes
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<String>, _>>()
            .map_err(io::Error::other)
            .and_then(|changes| {
                let mut lines = report::Lines::new();
                lines.lead(&format!(
                    "Classified the candidate against the baseline. {}.",
                    report::counted(changes.len(), "change")
                ));
                lines.pairs(&[
                    ("profile", "authoring".to_owned()),
                    (
                        "baseline assurance",
                        match report.baseline_assurance {
                            BaselineAssurance::RuntimeBound => "runtime_bound",
                            BaselineAssurance::IntegrityOnly => "integrity_only",
                        }
                        .to_owned(),
                    ),
                    (
                        "baseline package revision",
                        report.diff.baseline_package_revision.clone(),
                    ),
                    (
                        "baseline registry revision",
                        report.diff.baseline_registry_revision.clone(),
                    ),
                    (
                        "candidate registry revision",
                        report.diff.candidate_registry_revision.clone(),
                    ),
                    ("changes", changes.len().to_string()),
                ]);
                if !changes.is_empty() {
                    lines.blank();
                    for change in &changes {
                        lines.bullet(change);
                    }
                }
                lines.findings(&report_findings(&report.findings));
                stdout.write_all(lines.finish().as_bytes())
            })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(stderr, "bregctl: output could not be written");
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
        {
            // A refusal is reported on stderr, and it is the whole report:
            // the lead sentence names the command that refused, and the
            // diagnostics below it carry their own severity and closing count.
            let mut lines = report::Lines::new();
            lines.lead(&format!("bregctl {} refused.", report.command));
            lines.refusal_findings(&report_findings(&report.diagnostics));
            stderr.write_all(lines.finish().as_bytes())
        }
    };
    if result.is_err() {
        let _ = writeln!(stderr, "bregctl: output could not be written");
        return ExitCode::from(OPERATIONAL_FAILURE_EXIT);
    }
    ExitCode::from(DOMAIN_REFUSAL_EXIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_breg::postgres::RoleMode;

    #[test]
    fn a_validator_reason_that_repeats_the_value_is_not_the_usage_message() {
        let refused = |reason: fn(&str) -> Result<String, String>, value: &str| {
            let error = clap::Command::new("bregctl")
                .arg(
                    clap::Arg::new("reference")
                        .long("reference")
                        .value_parser(reason),
                )
                .try_get_matches_from(["bregctl", "--reference", value])
                .unwrap_err();
            usage_message(&error, &[])
        };
        let echoing = refused(
            |value| Err(format!("--reference refused {value}")),
            "sentinel-7f3a9c",
        );
        assert!(!echoing.contains("sentinel-7f3a9c"), "{echoing}");
        assert!(
            echoing.starts_with("invalid value for --reference <reference>"),
            "{echoing}"
        );
        let value_free = refused(
            |_| Err("--reference must not contain control characters".to_owned()),
            "change\n42",
        );
        assert!(
            value_free.starts_with("--reference must not contain control characters\n"),
            "{value_free}"
        );
    }

    fn reconcile_lifecycle_outcome(outcome: &'static str) -> ReconcileLifecycleOutcome {
        ReconcileLifecycleOutcome {
            outcome,
            executed: false,
            maintenance_status: Some("failed".to_owned()),
            maintenance_target_package_digest: Some("rev-2".to_owned()),
            active_package_digest: Some("rev-1".to_owned()),
            target_package_digest: "rev-2".to_owned(),
            target_catalog_finding: None,
            active_catalog_finding: None,
            unresolvable_reason: None,
            plan_kind: "compiled_additive",
            migration_step_count: 0,
            reviewed_plan_closed: None,
            durable_step_progress: None,
        }
    }

    #[test]
    fn a_refused_active_package_names_package_root_apart_from_the_target() {
        let diagnostic = |error| {
            let report = serde_json::to_value(lifecycle_failure("plan", error))
                .expect("the failure report serializes");
            report["diagnostics"][0].clone()
        };
        let target = diagnostic(ApplyLifecycleError::TargetPackage(
            PackageError::LegacyFormat,
        ));
        assert_eq!(target["code"], "apply.package.refused");
        assert_eq!(target["path"], "package");
        assert_eq!(
            target["message"],
            registry_breg::package::LEGACY_PACKAGE_FORMAT
        );

        // A database a release before the activation ledger activated is
        // adopted by the package package.root names, and that release's
        // packages all use the retired format.
        let active = diagnostic(ApplyLifecycleError::CurrentPackage(
            PackageError::LegacyFormat,
        ));
        assert_eq!(active["code"], "apply.package.refused");
        assert_eq!(active["path"], "package.root");
        let message = active["message"].as_str().expect("the message renders");
        assert!(message.contains("package.root"), "{message}");
        assert!(message.contains("`bregctl package`"), "{message}");

        let active = diagnostic(ApplyLifecycleError::CurrentPackage(
            PackageError::Permissions,
        ));
        assert_eq!(active["path"], "package.root");
        assert!(
            active["message"]
                .as_str()
                .is_some_and(|message| message.contains("package.root")),
            "{active}"
        );
    }

    #[test]
    fn migration_reconcile_reports_an_unresolvable_outcome_as_a_refusal() {
        match migration_reconcile_report(reconcile_lifecycle_outcome("unresolvable")) {
            Ok(_) => panic!("an unresolvable outcome must not be reported as ok: true"),
            Err(report) => {
                assert!(!report.ok);
                assert_eq!(
                    report.diagnostics[0].code,
                    "migration.reconcile.outcome.unresolvable"
                );
            }
        }
    }

    #[test]
    fn migration_reconcile_refusal_keeps_the_assessed_findings() {
        let mut outcome = reconcile_lifecycle_outcome("unresolvable");
        outcome.target_catalog_finding = Some("target_finding_canary");
        outcome.active_catalog_finding = Some("active_finding_canary");
        outcome.unresolvable_reason = Some("reason_canary");
        let Err(report) = migration_reconcile_report(outcome) else {
            panic!("an unresolvable outcome must be refused");
        };
        let message = &report.diagnostics[0].message;
        for finding in [
            "target_finding_canary",
            "active_finding_canary",
            "reason_canary",
        ] {
            assert!(
                message.contains(finding),
                "the refusal must keep {finding}: {message}"
            );
        }
    }

    #[test]
    fn migration_reconcile_reports_a_completable_outcome_as_success() {
        match migration_reconcile_report(reconcile_lifecycle_outcome("completable")) {
            Ok(report) => {
                assert!(report.ok);
                assert_eq!(report.outcome.outcome, "completable");
            }
            Err(_) => panic!("a completable outcome is an ordinary assessment success"),
        }
    }

    #[test]
    fn data_import_success_names_the_ingestion_run_it_drove() {
        let report = DataImportSuccessReport {
            ok: true,
            command: "data import",
            package_revision: "package-revision".to_owned(),
            schema_fingerprint: "schema-fingerprint".to_owned(),
            entity_id: "record".to_owned(),
            profile_id: "operator".to_owned(),
            operation: DataOperationArg::Create,
            run_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            input_length: 128,
            item_count: 3,
            completed_chunk_count: 2,
            committed_items: 3,
            complete: true,
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write_data_import_success(&report, OutputFormat::Json, &mut stdout, &mut stderr);
        let rendered = serde_json::from_slice::<serde_json::Value>(&stdout).unwrap();
        assert_eq!(rendered["runId"], "00000000-0000-4000-8000-000000000001");
        assert_eq!(rendered["complete"], true);

        stdout.clear();
        write_data_import_success(&report, OutputFormat::Human, &mut stdout, &mut stderr);
        let rendered = String::from_utf8(stdout).unwrap();
        assert!(rendered.contains("ingestion run"));
        assert!(rendered.contains("00000000-0000-4000-8000-000000000001"));
    }

    #[test]
    fn init_template_conflicts_with_every_flag_that_shapes_a_derived_project() {
        assert!(
            Cli::try_parse_from(["bregctl", "init", "project", "--template", "seed-lots"]).is_ok()
        );
        for conflicting in [
            vec!["--from", "publicschema"],
            vec!["--from", "publicschema", "--selection", "selection.yaml"],
            vec!["--from", "publicschema", "--starter", "household"],
        ] {
            let mut arguments = vec!["bregctl", "init", "project", "--template", "seed-lots"];
            arguments.extend(conflicting);
            assert!(Cli::try_parse_from(&arguments).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn init_template_publishes_and_enforces_every_shipped_id() {
        let mut init = command()
            .find_subcommand("init")
            .expect("init command exists")
            .clone();
        let template = init
            .get_arguments()
            .find(|argument| argument.get_id() == "template")
            .expect("template argument exists");
        let possible_values = template
            .get_value_parser()
            .possible_values()
            .expect("template has possible values")
            .map(|value| value.get_name().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(possible_values, starters::ids());

        let help = init.render_long_help().to_string();
        for id in starters::ids() {
            assert!(help.contains(id), "init help omits {id}: {help}");
        }

        let error = Cli::try_parse_from([
            "bregctl",
            "init",
            "project",
            "--template",
            "not-a-real-starter",
        ])
        .expect_err("an unknown template must be refused by Clap");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
        let message = error.to_string();
        for id in starters::ids() {
            assert!(
                message.contains(id),
                "invalid-value error omits {id}: {message}"
            );
        }
    }

    #[test]
    fn request_retention_cleanup_accepts_config_without_request_scope() {
        let parsed = Cli::try_parse_from([
            "bregctl",
            "request-retention",
            "cleanup-attachments",
            "--runtime-config",
            "/tmp/runtime.yaml",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::RequestRetention(RequestRetentionArgs {
                command: RequestRetentionCommand::CleanupAttachments(_)
            })
        ));
        let removed = Cli::try_parse_from([
            "bregctl",
            "request-retention",
            "cleanup-attachments",
            "--config",
            "/tmp/runtime.yaml",
        ])
        .expect_err("the removed --config alias is refused");
        assert_eq!(removed.kind(), clap::error::ErrorKind::UnknownArgument);
        let report = AttachmentCleanupSuccessReport {
            ok: true,
            command: "request-retention cleanup-attachments",
            outcome: registry_breg::request_retention::AttachmentCleanup {
                pending_external_deletions: 2,
                external_deletion_tombstones: 3,
            },
        };
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::json!({
                "ok":true, "command":"request-retention cleanup-attachments",
                "pendingExternalDeletions":2, "externalDeletionTombstones":3,
            })
        );
    }

    #[test]
    fn review_recovery_ineligible_diagnostic_names_reason_state_and_code() {
        let report = review_recovery_failure(
            "review-recovery resubmit",
            ReviewRecoveryCliError::Ineligible {
                reason: "request-erased",
                state: "failed".to_owned(),
                code: Some("result-poll-attempts-exhausted".to_owned()),
            },
        );
        let encoded = serde_json::to_string(&report).expect("report encodes");
        assert!(encoded.contains("review_recovery.submission.ineligible"));
        assert!(encoded
            .contains("reason request-erased, state failed, code result-poll-attempts-exhausted"));
    }

    #[test]
    fn request_retention_binding_diagnostic_identifies_recovery() {
        let report = request_retention_failure(
            "request-retention erase",
            RequestRetentionCliError::AttachmentStorageBindingMismatch,
        );
        let value = serde_json::to_value(report).unwrap();
        let encoded = value.to_string();
        assert!(encoded.contains("request_retention.attachment_storage.binding_mismatch"));
        assert!(encoded.contains("restore the original attachment storage binding"));
    }

    use registry_breg::compile_project;

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn create() -> Self {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
                ".bregctl-unit-test-{}-{}",
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

    /// The rendering a pipe, a file, or a test harness receives.
    ///
    /// The renderer always writes the ANSI attributes and `main_entry` wraps
    /// the process streams in an `AutoStream` that strips them for anything
    /// that is not a terminal. A test writes to a `Vec`, so it strips them
    /// here and pins the bytes a reader of a captured transcript would see.
    fn plain(rendered: &[u8]) -> String {
        let rendered = String::from_utf8(rendered.to_vec()).expect("output is UTF-8");
        anstream::adapter::strip_str(&rendered).to_string()
    }

    fn nested_artifact_path(levels: u32, leaf: &str) -> String {
        let mut path = String::new();
        for level in 0..levels {
            path.push_str(&format!("d{level}/"));
        }
        path.push_str(leaf);
        path
    }

    #[test]
    fn a_generated_artifact_tree_the_tool_could_not_remove_is_refused_before_staging() {
        let directory = TestDirectory::create();
        let files = BTreeMap::from([(
            nested_artifact_path(MAX_REMOVE_TREE_DEPTH, "schema.sql"),
            b"generated".to_vec(),
        )]);

        let refused = write_source_files(&directory.path.join("out"), &files)
            .expect_err("an artifact tree deeper than the removal bound is refused");

        assert_eq!(refused.code, "artifact.path.invalid");
        // The refusal lands before the first artifact is created, and the
        // staging directory the writer had already made is removed, so nothing
        // survives that the tool could not clean up afterwards.
        assert!(!directory.path.join("out").exists());
        assert_eq!(fs::read_dir(&directory.path).unwrap().count(), 0);
    }

    #[test]
    fn a_generated_artifact_tree_at_the_removal_bound_publishes_and_stays_removable() {
        let directory = TestDirectory::create();
        let relative = nested_artifact_path(MAX_REMOVE_TREE_DEPTH - 1, "schema.sql");
        let files = BTreeMap::from([(relative.clone(), b"generated".to_vec())]);

        write_source_files(&directory.path.join("out"), &files)
            .expect("an artifact tree within the removal bound publishes");

        assert_eq!(
            fs::read(directory.path.join("out").join(&relative)).unwrap(),
            b"generated"
        );
        // What the writer accepts, the removal reaches: the deepest tree it
        // will create is one this tool can still take away.
        SafeDir::resolve(&directory.path)
            .expect("the test directory resolves")
            .remove_tree(OsStr::new("out"))
            .expect("the published tree is within the removal bound");
    }

    #[test]
    fn rhai_planner_capture_enforces_normalized_relative_paths_and_source_bound() {
        let directory = TestDirectory::create();
        fs::create_dir_all(directory.path.join("planners")).unwrap();
        fs::write(
            directory.path.join("planners/request.rhai"),
            b"fn plan(ctx) { #{ effects: [] } }\n",
        )
        .unwrap();
        let origin = SafeDir::resolve(&directory.path).expect("the test directory resolves");
        let captured = load_planner_asset_files(
            &origin,
            BTreeMap::from([(
                "planners/request.rhai".to_owned(),
                "registry.yaml".to_owned(),
            )]),
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
            &origin,
            BTreeMap::from([(
                "planners/oversized.rhai".to_owned(),
                "registry.yaml".to_owned(),
            )]),
        )
        .unwrap_err();
        assert_eq!(oversized.code, "source.file.bounds");
    }

    #[test]
    fn wasm_module_capture_enforces_normalized_relative_paths_and_module_bound() {
        let directory = TestDirectory::create();
        fs::create_dir_all(directory.path.join("wasm")).unwrap();
        let module_bytes = b"\0asm\x01\0\0\0module-bytes".to_vec();
        fs::write(
            directory.path.join("wasm/handler.wasm"),
            module_bytes.clone(),
        )
        .unwrap();
        let origin = SafeDir::resolve(&directory.path).expect("the test directory resolves");
        let captured = load_wasm_module_asset_files(
            &origin,
            BTreeMap::from([(
                "wasm/handler.wasm".to_owned(),
                "actions[register-person].handler.module".to_owned(),
            )]),
        )
        .expect("safe project-relative module is captured");
        assert_eq!(captured[0].path, "wasm/handler.wasm");
        assert_eq!(captured[0].bytes, module_bytes);

        for path in [
            "../handler.wasm",
            "/handler.wasm",
            "wasm//handler.wasm",
            "wasm/handler.rhai",
            "wasm\\handler.wasm",
        ] {
            assert_eq!(
                validate_wasm_module_asset_path("registry.yaml", path)
                    .unwrap_err()
                    .code,
                "source.wasm_module.path_unsafe"
            );
        }

        fs::write(
            directory.path.join("wasm/oversized.wasm"),
            vec![b'x'; registry_breg::wasm_handler::MAXIMUM_WASM_MODULE_BYTES + 1],
        )
        .unwrap();
        let oversized = load_wasm_module_asset_files(
            &origin,
            BTreeMap::from([("wasm/oversized.wasm".to_owned(), "registry.yaml".to_owned())]),
        )
        .unwrap_err();
        assert_eq!(oversized.code, "source.file.bounds");
    }

    /// The asset readers refuse an escaping path themselves, so the module and
    /// planner path rules are not the only thing between a declared asset and a
    /// file outside the directory the module was listed in.
    #[test]
    fn an_asset_path_that_climbs_out_of_its_origin_is_refused_before_any_component_opens() {
        let directory = TestDirectory::create();
        fs::create_dir_all(directory.path.join("modules/persons")).unwrap();
        fs::write(directory.path.join("modules/outside.sql"), b"outside\n").unwrap();
        let origin = SafeDir::resolve(&directory.path.join("modules/persons"))
            .expect("the module directory resolves");

        for asset_path in ["../outside.sql", "/etc/passwd"] {
            let refused = open_asset_entry(
                &origin,
                asset_path,
                || module_asset_path_diagnostic("persons"),
                |error| {
                    path_diagnostic(
                        error,
                        "source.module_asset.missing",
                        "modules/persons",
                        "the required authoring source is not available",
                        "authoring sources must be regular files and must not be symbolic links",
                    )
                },
            )
            .expect_err("an escaping asset path is refused");

            // The path arm answered, so no component of the escaping path was
            // opened on the way to a missing-source refusal.
            assert_eq!(refused.code, "source.module_asset.path_unsafe");
        }
        assert_eq!(
            fs::read(directory.path.join("modules/outside.sql")).unwrap(),
            b"outside\n"
        );
    }

    #[test]
    fn project_planner_test_parser_requires_entity_and_request_file() {
        let parsed = Cli::try_parse_from([
            "bregctl",
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
        assert_eq!(args.entity.as_deref(), Some("request"));
        assert_eq!(args.request, Some(PathBuf::from("request.json")));
        assert!(Cli::try_parse_from([
            "bregctl",
            "project",
            "planner-test",
            "project",
            "--entity",
            "request",
        ])
        .is_err());
    }

    #[test]
    fn v2_without_capabilities_explains_external_lifecycle_and_zero_call_ceiling() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/person-registration-rhai");
        let mut project = registry_breg::contract::parse_project_yaml(
            &fs::read(root.join("registry.yaml")).unwrap(),
        )
        .unwrap();
        let assets = project
            .actions
            .iter_mut()
            .map(|action| {
                let handler = action.handler.as_mut().unwrap();
                let script = handler.script().expect("a rhai handler").to_owned();
                handler.handler = registry_breg::contract::HookHandlerSource::Rhai {
                    script: script.clone(),
                    abi: Some(registry_breg::contract::ACTION_HANDLER_ABI_V2.to_owned()),
                };
                registry_breg::contract::ModuleAssetSource {
                    module: None,
                    bytes: fs::read(root.join(&script)).unwrap(),
                    path: script,
                }
            })
            .collect::<Vec<_>>();
        let compiled = registry_breg::compiler::compile_project_with_assets(
            &project,
            &[],
            &assets,
            registry_breg::compiler::CompileProfile::Authoring,
        )
        .unwrap();
        let explanation = explain_actions(&compiled).unwrap();
        for action in explanation["actions"].as_array().unwrap() {
            assert_eq!(action["evidence"]["maximumCalls"], 0);
            assert_eq!(action["evidence"]["maximumConcurrentEvaluations"], 8);
            assert_eq!(
                action["handler"]["evaluation"],
                "outside_postgres_after_admission_and_receipt_preflight"
            );
        }
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
        let entity = &compiled.entities()["person-name-change-request"];
        let schema: Value = serde_json::from_slice(
            &compiled
                .artifacts()
                .get("generated/schemas/person-name-change-request.schema.json")
                .unwrap()
                .bytes,
        )
        .unwrap();
        let fields = request["fields"].as_array().unwrap();
        assert!(!fields.is_empty());
        assert_eq!(fields.len(), entity.stored_fields.len());
        for (field, descriptor) in entity.stored_fields.iter().zip(fields) {
            assert_eq!(descriptor["field"], field.logical.id);
            assert_eq!(descriptor["apiName"], field.logical.api_name);
            assert_eq!(
                descriptor["schema"],
                schema["properties"][&field.logical.api_name]
            );
        }
        assert_eq!(request["planner"]["kind"], "rhai");
        assert_eq!(
            request["planner"]["abi"],
            registry_breg::contract::CHANGE_REQUEST_PLAN_ABI_V1
        );
        assert_eq!(
            request["planner"]["rhaiVersion"],
            registry_breg::change_request::CHANGE_REQUEST_PLANNER_RHAI_VERSION
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
        assert_eq!(request["review"], json!({"mode": "none"}));
        assert_eq!(request["onApproved"], json!({"mode": "manual"}));
        assert_eq!(request["application"], json!({}));
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
            OsString::from("bregctl"),
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
        assert!(value.get("disposition").is_none());
        assert!(value.get("queueReason").is_none());
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
                    }]
                }
            }
            "#,
        )
        .unwrap();
        let dynamic = match planner_test(&ProjectPlannerTestArgs {
            project: dynamic_project,
            entity: Some("person-name-change-request".to_owned()),
            request: Some(request_path),
            action: None,
            input: None,
            expect: None,
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
            .join("../../products/breg/starters/public-organizations/core")
            .canonicalize()
            .expect("declarative fixture canonicalizes");
        assert_planner_test_failure(
            &declarative,
            "name-correction",
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
            entity: Some(entity.to_owned()),
            request: Some(request.to_owned()),
            action: None,
            input: None,
            expect: None,
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
            .join("../../products/breg/acceptance/person-name-change-rhai")
            .canonicalize()
            .expect("planner fixture canonicalizes")
    }

    #[test]
    fn a_half_reserved_export_pair_names_the_file_that_is_missing() {
        let checkpoint = serde_json::to_value(data_lifecycle_failure(
            "data export",
            "data.export",
            DataLifecycleError::ExportPair(ExportPairState::CheckpointMissing),
        ))
        .expect("the failure report serializes");
        assert_eq!(
            checkpoint["diagnostics"][0]["code"],
            "data.export.checkpoint.missing"
        );
        assert_eq!(checkpoint["diagnostics"][0]["path"], "checkpoint");
        assert!(checkpoint["diagnostics"][0]["message"]
            .as_str()
            .expect("the message renders")
            .contains("without the checkpoint"));

        let output = serde_json::to_value(data_lifecycle_failure(
            "data export",
            "data.export",
            DataLifecycleError::ExportPair(ExportPairState::OutputMissing),
        ))
        .expect("the failure report serializes");
        assert_eq!(
            output["diagnostics"][0]["code"],
            "data.export.output.missing"
        );
        assert_eq!(output["diagnostics"][0]["path"], "output");
        assert!(output["diagnostics"][0]["message"]
            .as_str()
            .expect("the message renders")
            .contains("without the output"));
    }

    #[test]
    fn a_blocked_or_refused_import_run_names_its_cause_and_next_step() {
        for (error, code, hint) in [
            (
                DataLifecycleError::ImportRunBlocked(Some(
                    BRegIngestionBlockedReason::ActivePackageChanged,
                )),
                "data.import.ingestion_run.blocked",
                "active package changed",
            ),
            (
                DataLifecycleError::ImportRunBlocked(Some(
                    BRegIngestionBlockedReason::ImportAuthorityClosed,
                )),
                "data.import.ingestion_run.import_authority_closed",
                "bregctl import-authority list",
            ),
            (
                DataLifecycleError::ImportRunBlocked(None),
                "data.import.ingestion_run.blocked",
                "blockedReason",
            ),
            (
                DataLifecycleError::IngestionRunPrecondition {
                    through_import: true,
                },
                "data.import.ingestion_run.import_authority_required",
                "bregctl import-authority list",
            ),
            (
                DataLifecycleError::IngestionRunPrecondition {
                    through_import: false,
                },
                "data.import.ingestion_run.precondition_failed",
                "precondition",
            ),
        ] {
            let report =
                serde_json::to_value(data_lifecycle_failure("data import", "data.import", error))
                    .expect("the failure report serializes");
            assert_eq!(report["diagnostics"][0]["code"], code);
            assert_eq!(report["diagnostics"][0]["path"], "ingestionRun");
            let message = report["diagnostics"][0]["message"]
                .as_str()
                .expect("the message renders");
            assert!(message.contains(hint), "{code}: {message}");
        }
    }

    #[test]
    fn import_authority_reports_name_the_bounds_in_both_formats() {
        use registry_breg::import_authority::{ImportAuthority, ImportAuthorityStatus};
        let opened_at = chrono::DateTime::parse_from_rfc3339("2026-09-25T10:00:00Z")
            .expect("instant parses")
            .with_timezone(&chrono::Utc);
        let authority = ImportAuthority {
            authority_id: uuid::Uuid::nil(),
            entity_id: "widget".to_owned(),
            profile_id: "loader".to_owned(),
            operation: "create".to_owned(),
            max_items: 10,
            committed_items: 4,
            input_digests: Vec::new(),
            activation_id: uuid::Uuid::nil(),
            opened_at,
            expires_at: opened_at + chrono::Duration::days(7),
            status: ImportAuthorityStatus::Open,
            closed_at: None,
        };
        let mut json_out = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_import_authority_success(
                "import-authority open",
                std::slice::from_ref(&authority),
                OutputFormat::Json,
                &mut json_out,
                &mut stderr,
            ),
            ExitCode::SUCCESS
        );
        let report: Value = serde_json::from_slice(&json_out).expect("report is JSON");
        assert_eq!(report["command"], "import-authority open");
        assert_eq!(report["authority"]["status"], "open");
        assert_eq!(report["authority"]["committedItems"], 4);
        assert_eq!(report["authority"]["maxItems"], 10);

        let mut listed = Vec::new();
        assert_eq!(
            write_import_authority_success(
                "import-authority list",
                &[authority],
                OutputFormat::Human,
                &mut listed,
                &mut stderr,
            ),
            ExitCode::SUCCESS
        );
        let listed = String::from_utf8(listed).expect("report is UTF-8");
        assert!(listed.contains("Listed the newest import authorities. 1 authority."));
        assert!(listed.contains("4 of 10"));
        assert!(listed.contains("none (any input)"));
        assert!(stderr.is_empty());
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
                "module",
                "generate",
                "dev",
                "examples",
                "explain",
                "diff",
                "package",
                "test",
                "apply",
                "plan",
                "status",
                "doctor",
                "verify",
                "migration",
                "history",
                "data",
                "webhook",
                "request-retention",
                "review-recovery",
                "evidence-retention",
                "import-authority",
                "instance-claim",
                "field-encryption"
            ]
        );
    }

    #[test]
    fn example_reports_show_native_results_and_next_command_in_both_formats() {
        let report = json!({"ok":true,"command":"examples run","project":"/local/project","scenario":"first-record","attempt":"attempt-id","captures":{"first-record":{"id":"returned-id","entity":"entry"}},"results":{"get":{"data":{"name":"Synthetic record"}}},"nextCommand":"bregctl examples run reviewed-change . --step submit"});
        let mut human = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_examples_success(&report, OutputFormat::Human, &mut human, &mut stderr),
            ExitCode::SUCCESS
        );
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("bregctl examples run succeeded."));
        assert!(human.contains("returned-id"));
        assert!(human.contains("Synthetic record"));
        assert!(human.contains("--step submit"));
        let mut json = Vec::new();
        assert_eq!(
            write_examples_success(&report, OutputFormat::Json, &mut json, &mut stderr),
            ExitCode::SUCCESS
        );
        assert_eq!(serde_json::from_slice::<Value>(&json).unwrap(), report);
        assert!(stderr.is_empty());
    }

    #[test]
    fn dev_reports_honour_the_requested_output_format() {
        let report = json!({
            "ok": true,
            "command": "dev",
            "status": "ready",
            "project": "/local/registry",
            "stateFile": "/local/registry/.breg/dev/state.json",
            "runtimeConfig": "/local/registry/.breg/dev/runtime.yaml",
            "bregUrl": "http://127.0.0.1:8090",
            "tokenEndpoint": "http://127.0.0.1:8091/token",
            "audience": "urn:breg:dev:local",
            "packageDigest": "sha256:package-1",
            "clients": [{
                "id": "operator",
                "accessProfiles": ["operator"],
                "clientIdFile": "/local/registry/.breg/dev/credentials/operator/client-id",
                "assertionKeyFile":
                    "/local/registry/.breg/dev/credentials/operator/assertion-key.jwk"
            }]
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_dev_success(&report, OutputFormat::Human, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert_eq!(
            plain(&stdout),
            "bregctl dev succeeded.\n\
             \x20 status          ready\n\
             \x20 project         /local/registry\n\
             \x20 breg url        http://127.0.0.1:8090\n\
             \x20 token endpoint  http://127.0.0.1:8091/token\n\
             \x20 audience        urn:breg:dev:local\n\
             \x20 package digest  sha256:package-1\n\
             \x20 state file      /local/registry/.breg/dev/state.json\n\
             \x20 runtime config  /local/registry/.breg/dev/runtime.yaml\n\
             \n\
             \x20 client operator\n\
             \x20   client id file      \
             /local/registry/.breg/dev/credentials/operator/client-id\n\
             \x20   assertion key file  \
             /local/registry/.breg/dev/credentials/operator/assertion-key.jwk\n"
        );
        assert!(stderr.is_empty());

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_dev_success(&report, OutputFormat::Json, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        let rendered = String::from_utf8(stdout).expect("output is UTF-8");
        assert_eq!(
            serde_json::from_str::<Value>(&rendered).expect("report is JSON"),
            report
        );
        assert!(rendered.ends_with("\n}\n"));
        assert!(stderr.is_empty());

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_dev_success(
                &json!({"ok": true, "command": "dev stop", "status": "stopped"}),
                OutputFormat::Human,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(
            plain(&stdout),
            "bregctl dev stop succeeded.\n\x20 status  stopped\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn dev_start_takes_no_detach_flag() {
        assert!(Cli::try_parse_from(["bregctl", "dev", "."]).is_ok());
        assert!(Cli::try_parse_from(["bregctl", "dev", "start", "."]).is_ok());
        for arguments in [
            vec!["bregctl", "dev", "--detach"],
            vec!["bregctl", "dev", "start", "--detach"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn dev_start_takes_no_mint_issuer_flags() {
        for arguments in [
            vec!["bregctl", "dev", "start", ".", "--mint-port", "8091"],
            vec!["bregctl", "dev", "start", ".", "--mint-bin", "/mint"],
        ] {
            let error = Cli::try_parse_from(&arguments).expect_err("unknown flag");
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn dev_names_its_project_the_way_every_other_command_does() {
        // `check`, `test`, `generate` and the rest take the project as their
        // positional argument, so `dev` does too, defaulting to the current
        // directory when it is absent. The clients file stays a flag because
        // a first start reads the project's own dev-clients.yaml without it.
        for arguments in [
            vec!["bregctl", "dev"],
            vec!["bregctl", "dev", "tutorial-work/project"],
            vec!["bregctl", "dev", "start", "tutorial-work/project"],
            vec!["bregctl", "dev", "stop", "tutorial-work/project"],
            vec![
                "bregctl",
                "dev",
                "stop",
                "tutorial-work/project",
                "--remove",
            ],
            vec![
                "bregctl",
                "dev",
                "tutorial-work/project",
                "--clients-file",
                "clients.yaml",
            ],
        ] {
            assert!(Cli::try_parse_from(&arguments).is_ok(), "{arguments:?}");
        }
        for arguments in [
            vec!["bregctl", "dev", "--project", "."],
            vec!["bregctl", "dev", "start", "--project", "."],
            vec!["bregctl", "dev", "stop", "--project", "."],
            // A project before the action would stop a different directory
            // than the one named, so the two forms do not combine.
            vec!["bregctl", "dev", "tutorial-work/project", "stop"],
            vec!["bregctl", "dev", "one", "two"],
            vec![
                "bregctl",
                "dev",
                "tutorial-work/project",
                "--clients",
                "clients.yaml",
            ],
        ] {
            assert!(Cli::try_parse_from(&arguments).is_err(), "{arguments:?}");
        }
    }

    #[test]
    fn dev_stop_reclaims_only_when_removal_is_explicit() {
        assert!(Cli::try_parse_from(["bregctl", "dev", "stop", "."]).is_ok());
        assert!(Cli::try_parse_from(["bregctl", "dev", "stop", ".", "--remove"]).is_ok());
        for arguments in [
            vec!["bregctl", "dev", "--remove"],
            vec!["bregctl", "dev", "start", "--remove"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn global_format_is_accepted_before_or_after_the_subcommand() {
        for arguments in [
            vec!["bregctl", "--format", "json", "check", "project"],
            vec!["bregctl", "check", "project", "--format", "json"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }

    #[test]
    fn history_rebaseline_takes_only_the_runtime_config_and_request_file() {
        let parsed = Cli::try_parse_from([
            "bregctl",
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
            "bregctl",
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
            "bregctl",
            "history",
            "erase",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--request-file",
            "/tmp/request.json",
            "--acknowledge-irreversible",
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
        assert!(args.acknowledge_irreversible);
        assert!(Cli::try_parse_from([
            "bregctl",
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
                scrubbed_ingestion_receipt_count: 1,
                scrubbed_request_target_count: 1,
                scrubbed_request_proposal_count: 0,
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
        assert!(rendered.contains("\"scrubbedIngestionReceiptCount\": 1"));
        assert!(!rendered.contains("018feaa0-68f9-4a45-b9e3-58436df07af7"));
        assert!(!rendered.contains("operator"));
        assert!(!rendered.contains("reason"));
    }

    #[test]
    fn doctor_success_output_is_stable_in_human_and_machine_formats() {
        for (format, expected) in [
            (
                OutputFormat::Human,
                "10 dependency checks passed.\n\
                 \u{20}\u{20}runtimeConfig        pass\n\
                 \u{20}\u{20}package              pass\n\
                 \u{20}\u{20}database             pass\n\
                 \u{20}\u{20}audit                pass\n\
                 \u{20}\u{20}cursor               pass\n\
                 \u{20}\u{20}authentication.oidc  pass\n\
                 \u{20}\u{20}eventDestinations    pass\n\
                 \u{20}\u{20}reviewBindings       pass\n\
                 \u{20}\u{20}authentication       pass\n\
                 \u{20}\u{20}fieldEncryption      pass\n\
                 \u{20}\u{20}roleMode             split\n",
            ),
            (
                OutputFormat::Json,
                "{\n  \"ok\": true,\n  \"command\": \"doctor\",\n  \"checked\": [\n    \"runtimeConfig\",\n    \"package\",\n    \"database\",\n    \"audit\",\n    \"cursor\",\n    \"authentication.oidc\",\n    \"eventDestinations\",\n    \"reviewBindings\",\n    \"authentication\",\n    \"fieldEncryption\"\n  ],\n  \"roleMode\": \"split\",\n  \"advisories\": []\n}\n",
            ),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            assert_eq!(
                write_doctor_success(&[], RoleMode::Split, format, &mut stdout, &mut stderr),
                ExitCode::SUCCESS
            );
            assert_eq!(plain(&stdout), expected);
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn doctor_says_what_one_role_mode_does_not_guard() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_doctor_success(
                &[],
                RoleMode::Single,
                OutputFormat::Human,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        let human = plain(&stdout);
        assert!(human.contains("roleMode             single\n"), "{human}");
        assert!(
            human
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("catches mistakes but not someone holding that credential"),
            "{human}"
        );

        let mut stdout = Vec::new();
        assert_eq!(
            write_doctor_success(
                &[],
                RoleMode::Single,
                OutputFormat::Json,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).expect("doctor JSON parses");
        assert_eq!(report["roleMode"], "single");
    }

    #[test]
    fn doctor_reports_postgres_advisories_after_the_passing_checks_without_failing() {
        let settings = registry_breg::postgres::BaselineSettings {
            max_connections: Some("20".to_owned()),
            superuser_reserved_connections: Some("3".to_owned()),
            reserved_connections: Some("1".to_owned()),
            autovacuum: Some("on".to_owned()),
            track_counts: Some("off".to_owned()),
            pg_stat_statements_installed: Some(false),
            pg_stat_statements_loaded: Some(false),
            pg_stat_statements_tracking: None,
        };
        let advisories = registry_breg::postgres::advise(&settings, 9);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_doctor_success(
                &advisories,
                RoleMode::Split,
                OutputFormat::Human,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let human = plain(&stdout);
        let (checks, advisory_section) = human
            .split_once("\n\nPostgreSQL advisories:\n")
            .expect("advisories follow the passing checks in their own section");
        assert!(checks.starts_with("10 dependency checks passed.\n"));
        assert!(checks.ends_with("roleMode             split"));
        assert_eq!(
            advisory_section,
            "  warning  postgres.connections.pool_over_half\n\
             \u{20}   one replica's runtime pool may take more than half of the connections PostgreSQL\n\
             \u{20}   leaves for ordinary roles, leaving too few for other replicas, operator tooling, and\n\
             \u{20}   maintenance\n\
             \u{20}   poolMaxSize                   9\n\
             \u{20}   maxConnections                20\n\
             \u{20}   superuserReservedConnections  3\n\
             \u{20}   reservedConnections           1\n\
             \u{20}   usableConnections             16\n\
             \u{20} warning  postgres.track_counts.off\n\
             \u{20}   track_counts is off, so autovacuum cannot tell which tables need vacuuming or\n\
             \u{20}   analyzing\n\
             \u{20} information  postgres.pg_stat_statements.unavailable\n\
             \u{20}   pg_stat_statements is not installed in this database, so per-statement timings are\n\
             \u{20}   unavailable when diagnosing load\n"
        );

        let mut stdout = Vec::new();
        assert_eq!(
            write_doctor_success(
                &advisories,
                RoleMode::Split,
                OutputFormat::Json,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let report: Value = serde_json::from_slice(&stdout).expect("doctor JSON parses");
        assert_eq!(report["ok"], true);
        assert_eq!(report["checked"].as_array().map(Vec::len), Some(10));
        assert_eq!(
            report["advisories"],
            json!([
                {
                    "code": "postgres.connections.pool_over_half",
                    "severity": "warning",
                    "message": advisories[0].message(),
                    "observed": {
                        "poolMaxSize": 9,
                        "maxConnections": 20,
                        "superuserReservedConnections": 3,
                        "reservedConnections": 1,
                        "usableConnections": 16
                    }
                },
                {
                    "code": "postgres.track_counts.off",
                    "severity": "warning",
                    "message": advisories[1].message(),
                    "observed": {}
                },
                {
                    "code": "postgres.pg_stat_statements.unavailable",
                    "severity": "information",
                    "message": advisories[2].message(),
                    "observed": {}
                }
            ])
        );
        let keys = std::str::from_utf8(&stdout).expect("doctor JSON is UTF-8");
        assert!(
            keys.find("\"poolMaxSize\"") < keys.find("\"usableConnections\""),
            "observed numbers keep the order the advisory decided them in"
        );
    }

    #[test]
    fn rebaselined_history_states_the_unavailable_range_as_a_note_not_a_step() {
        let report = HistoryRebaselineSuccessReport {
            ok: true,
            command: "history rebaseline",
            outcome: HistoryRebaselineLifecycleOutcome {
                package_revision: "pkg-1".to_owned(),
                baseline_position: 42,
                verified_entity_count: 1,
                verified_record_count: 2,
                previous_coverage_baseline_position: 7,
                previous_unavailable_after_position: None,
            },
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        assert_eq!(
            write_history_rebaseline_success(
                &report,
                OutputFormat::Human,
                &mut stdout,
                &mut stderr
            ),
            ExitCode::SUCCESS
        );
        let rendered = plain(&stdout);
        assert!(
            !rendered.contains("Next:"),
            "a statement about the rebaselined history is not a step: {rendered}"
        );
        assert!(
            rendered
                .ends_with("\n  Snapshot references before the new baseline remain unavailable.\n"),
            "{rendered}"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn an_access_explanation_names_the_entity_and_the_profile_it_groups() {
        let explanation = json!({
            "scopeMatching": "all required scopes must be present",
            "purposeMatching": "",
            "rowMatching": "",
            "profileSelection": "",
            "entities": [{
                "entity": "record",
                "classification": "internal",
                "requirements": null,
                "profiles": [{
                    "id": "record-reader",
                    "principalClaim": "registry_principal",
                }],
            }],
        });
        let mut lines = report::Lines::new();

        push_access_explanation(&explanation, &mut lines);

        let rendered = plain(lines.finish().as_bytes());
        assert!(
            rendered.contains("\n  entity record (internal)\n"),
            "the entity group names what it groups: {rendered}"
        );
        assert!(
            rendered.contains("\n    profile record-reader\n"),
            "the profile group names what it groups: {rendered}"
        );
    }

    #[test]
    fn a_fixture_run_names_its_journeys_the_way_an_export_names_its_fields() {
        for (journeys, expected) in [
            (Vec::new(), "successful journeys  none\n"),
            (
                vec![
                    "package-record-list".to_owned(),
                    "package-record-get".to_owned(),
                ],
                "successful journeys  package-record-list, package-record-get\n",
            ),
        ] {
            let report = SchemaTestSuccessReport {
                ok: true,
                command: "test",
                profile: ProfileArg::Production,
                registry_revision: "sha256:registry-1".to_owned(),
                schema_fingerprint: "sha256:1111".to_owned(),
                successful_journey_ids: journeys,
                receipt: ArtifactReport {
                    path: "result.json".to_owned(),
                    media_type: "application/json".to_owned(),
                    sha256: "sha256:3333".to_owned(),
                    byte_length: 2,
                },
                diagnostics: Vec::new(),
            };
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            assert_eq!(
                write_schema_test_success(&report, OutputFormat::Human, &mut stdout, &mut stderr),
                ExitCode::SUCCESS
            );
            let rendered = plain(&stdout);
            assert!(rendered.contains(expected), "{rendered}");
            assert!(
                !rendered.contains("baseline_fingerprint_drift"),
                "{rendered}"
            );
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn a_fixture_run_over_a_drifted_baseline_reports_the_drift_in_both_formats() {
        let signed = format!("sha256:{}", "1".repeat(64));
        let measured = format!("sha256:{}", "2".repeat(64));
        let report = SchemaTestSuccessReport {
            ok: true,
            command: "test",
            profile: ProfileArg::Production,
            registry_revision: "sha256:registry-2".to_owned(),
            schema_fingerprint: "sha256:3333".to_owned(),
            successful_journey_ids: vec!["package-record-list".to_owned()],
            receipt: ArtifactReport {
                path: "result.json".to_owned(),
                media_type: "application/json".to_owned(),
                sha256: "sha256:5555".to_owned(),
                byte_length: 2,
            },
            diagnostics: vec![baseline_fingerprint_drift_finding(
                &BaselineFingerprintDrift {
                    signed: signed.clone(),
                    measured: measured.clone(),
                },
            )],
        };

        let mut json = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_schema_test_success(&report, OutputFormat::Json, &mut json, &mut stderr),
            ExitCode::SUCCESS
        );
        let value: serde_json::Value = serde_json::from_slice(&json).expect("report is JSON");
        assert_eq!(value["ok"], true);
        let finding = &value["diagnostics"][0];
        assert_eq!(
            finding["code"],
            "migration.rehearsal.baseline_fingerprint_drift"
        );
        assert_eq!(finding["severity"], "finding");
        let message = finding["message"].as_str().expect("message is a string");
        for expected in [
            signed.as_str(),
            measured.as_str(),
            "apply checks the live database",
        ] {
            assert!(message.contains(expected), "{message}");
        }

        let mut human = Vec::new();
        assert_eq!(
            write_schema_test_success(&report, OutputFormat::Human, &mut human, &mut stderr),
            ExitCode::SUCCESS
        );
        let rendered = plain(&human);
        assert!(rendered.starts_with("Fixture run passed."), "{rendered}");
        assert!(
            rendered.contains("migration.rehearsal.baseline_fingerprint_drift"),
            "{rendered}"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn legacy_json_profile_and_full_generate_forms_are_not_accepted() {
        for arguments in [
            vec!["bregctl", "--json", "check", "project"],
            vec!["bregctl", "check", "project", "--profile", "production"],
            vec!["bregctl", "generate", "project", "--output", "out"],
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
    permissions:
      - entity: record
        rowBoundaries: []
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
                    .starts_with(".bregctl-stage-")
            }));
    }

    #[test]
    fn rebaseline_history_diagnostics_point_at_the_retained_history() {
        use registry_breg::history_rebaseline::HistoryRebaselineError;

        for (error, code) in [
            (
                HistoryRebaselineError::UnindexedRevisions,
                "history.rebaseline.revisions.unindexed",
            ),
            (
                HistoryRebaselineError::LiveHistoryMismatch,
                "history.rebaseline.live_rows.unverified",
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
        registry_breg::runtime_config::parse_runtime_config_with_env(raw, |_| None)
            .expect("the initialized runtime example parses");
    }

    /// Deterministic ancestor-swap regressions for the authoring, module lock,
    /// migration, and generated-output surfaces this module owns. They run
    /// wherever the descriptor-relative primitive exists.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod ancestor_swap {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        #[test]
        fn an_authoring_source_read_after_an_ancestor_swap_reads_only_the_named_file() {
            let tree = race_tree();
            let named = tree.named("registry.yaml");
            fs::write(&named, b"genuine\n").unwrap();
            fs::write(tree.outside("registry.yaml"), b"decoy\n").unwrap();

            let guard = tree.arm();
            let bytes = read_bounded_source_file(
                &named,
                "source.project.missing",
                "registry.yaml",
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )
            .unwrap();
            drop(guard);

            assert_eq!(bytes, b"genuine\n");
            // The window is real: the same pathname now reaches the tree the
            // operator never named.
            assert_eq!(fs::read(&named).unwrap(), b"decoy\n");
        }

        /// A module that declares derived SQL and both Rhai entry points, so
        /// each declared asset stays bound to the module's directory descriptor.
        const MODULE_WITH_ASSETS: &[u8] = br#"id: persons
version: 0.1.0
extendEntities:
  - entity: person
    derived:
      - id: person-summary
        sql: sql/summary.sql
        key: id
    changeRequest:
      planner:
        kind: rhai
        script: planners/person.rhai
        abi: registry.change-request-plan/v1
      review: {mode: none}
actions:
  - id: normalize-person
    handler:
      kind: rhai
      script: handlers/person.rhai
      abi: registry.action-handler/v1
      writes: []
"#;

        fn plant_module_with_assets(root: &Path, sql: &[u8], planner: &[u8], handler: &[u8]) {
            fs::create_dir_all(root.join("modules/persons/sql")).unwrap();
            fs::create_dir_all(root.join("modules/persons/planners")).unwrap();
            fs::create_dir_all(root.join("modules/persons/handlers")).unwrap();
            fs::write(root.join("modules/persons/module.yaml"), MODULE_WITH_ASSETS).unwrap();
            fs::write(root.join("modules/persons/sql/summary.sql"), sql).unwrap();
            fs::write(root.join("modules/persons/planners/person.rhai"), planner).unwrap();
            fs::write(root.join("modules/persons/handlers/person.rhai"), handler).unwrap();
        }

        #[test]
        fn module_assets_read_after_an_ancestor_swap_carry_the_listed_module_bytes() {
            let tree = race_tree();
            let project = tree.named_directory();
            plant_module_with_assets(
                &project,
                b"genuine sql\n",
                b"genuine planner\n",
                b"genuine handler\n",
            );
            plant_module_with_assets(
                &tree.outside_directory(),
                b"decoy sql\n",
                b"decoy planner\n",
                b"decoy handler\n",
            );

            let sources = read_module_yaml_files(read_module_directory_names(&project).unwrap())
                .expect("the listed module source reads");
            let module = parse_module_yaml(&sources[0].bytes).expect("the module source parses");
            // The ancestor becomes a real directory holding the decoy assets, so
            // an asset read that resolved its pathname again would reach them
            // without meeting a symbolic link.
            tree.swap_ancestor_directory();
            let assets = load_module_asset_files(&sources[0].directory, "persons", &module)
                .expect("the module assets read");

            let captured = assets
                .iter()
                .map(|asset| (asset.path.as_str(), asset.bytes.as_slice()))
                .collect::<Vec<_>>();
            assert_eq!(
                captured,
                vec![
                    ("handlers/person.rhai", b"genuine handler\n".as_slice()),
                    ("planners/person.rhai", b"genuine planner\n".as_slice()),
                    ("sql/summary.sql", b"genuine sql\n".as_slice()),
                ]
            );
            // The window is real: the same pathnames now reach the decoys.
            assert_eq!(
                fs::read(project.join("modules/persons/sql/summary.sql")).unwrap(),
                b"decoy sql\n"
            );
            assert_eq!(
                fs::read(project.join("modules/persons/planners/person.rhai")).unwrap(),
                b"decoy planner\n"
            );
            assert_eq!(
                fs::read(project.join("modules/persons/handlers/person.rhai")).unwrap(),
                b"decoy handler\n"
            );
        }

        #[test]
        fn module_sources_listed_before_an_ancestor_swap_are_read_from_the_listed_directory() {
            let tree = race_tree();
            let project = tree.named_directory();
            fs::create_dir_all(project.join("modules/persons")).unwrap();
            fs::write(project.join("modules/persons/module.yaml"), b"genuine\n").unwrap();
            let outside = tree.outside_directory();
            fs::create_dir_all(outside.join("modules/persons")).unwrap();
            fs::write(outside.join("modules/persons/module.yaml"), b"decoy\n").unwrap();

            let modules = read_module_directory_names(&project).unwrap();
            assert_eq!(modules.names, ["persons"]);
            // The ancestor becomes a real directory holding the decoy, so a
            // read that resolved the pathname again would reach it without
            // meeting a symbolic link.
            tree.swap_ancestor_directory();
            let files = read_module_yaml_files(modules).unwrap();

            assert_eq!(files.len(), 1);
            assert_eq!(files[0].id, "persons");
            assert_eq!(files[0].bytes, b"genuine\n");
            assert_eq!(
                fs::read(project.join("modules/persons/module.yaml")).unwrap(),
                b"decoy\n"
            );
        }

        #[test]
        fn generated_output_publication_after_an_ancestor_swap_publishes_only_in_the_named_tree() {
            let tree = race_tree();
            let files = BTreeMap::from([
                ("schema.sql".to_owned(), b"generated".to_vec()),
                ("nested/plan.json".to_owned(), b"nested".to_vec()),
            ]);

            let guard = tree.arm();
            write_source_files(&tree.named("out"), &files).unwrap();
            drop(guard);

            assert_eq!(
                fs::read(tree.moved("out/schema.sql")).unwrap(),
                b"generated"
            );
            assert_eq!(
                fs::read(tree.moved("out/nested/plan.json")).unwrap(),
                b"nested"
            );
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }

        #[test]
        fn an_output_directory_that_is_already_taken_is_refused_through_the_held_parent() {
            let tree = race_tree();
            let files = BTreeMap::from([("schema.sql".to_owned(), b"generated".to_vec())]);
            fs::create_dir(tree.named("out")).unwrap();
            fs::write(tree.named("out/kept.txt"), b"kept").unwrap();
            // The tree the operator never named has no `out`, so a refusal
            // decided by pathname after the swap would not fire at all.
            let guard = tree.arm();
            let refused = write_source_files(&tree.named("out"), &files)
                .expect_err("an output directory that already exists is refused");
            drop(guard);

            assert_eq!(refused.code, "output.destination.invalid");
            assert_eq!(fs::read(tree.moved("out/kept.txt")).unwrap(), b"kept");
            assert_eq!(tree.outside_entries(), vec!["target".to_owned()]);
        }

        #[test]
        fn a_module_lock_write_after_an_ancestor_swap_rewrites_only_the_named_file() {
            let tree = race_tree();
            fs::write(tree.named("registry.yaml"), b"original\n").unwrap();
            fs::write(tree.outside("registry.yaml"), b"decoy\n").unwrap();

            let guard = tree.arm();
            write_project_registry(&tree.named_directory(), b"original\n", b"locked\n").unwrap();
            drop(guard);

            assert_eq!(fs::read(tree.moved("registry.yaml")).unwrap(), b"locked\n");
            assert_eq!(fs::read(tree.outside("registry.yaml")).unwrap(), b"decoy\n");
        }

        #[test]
        fn a_bounded_source_read_records_the_identity_of_the_file_it_read() {
            let tree = race_tree();
            let named = tree.named("registry.yaml");
            fs::write(&named, b"original\n").unwrap();
            fs::write(tree.named("decoy.yaml"), b"decoy\n").unwrap();

            let entry = SafeEntry::resolve(&named).unwrap();
            let (bytes, metadata) = read_bounded_source_entry_with_identity(
                &entry,
                "source.project.missing",
                "registry.yaml",
                AUTHORED_SOURCE_REDERIVATION_MAX_BYTES,
            )
            .unwrap();

            // Relinking the name after the read leaves the reported identity
            // alone, so a caller that records it holds the file whose bytes it
            // compared rather than whatever the name reaches next.
            fs::rename(tree.named("decoy.yaml"), &named).unwrap();
            let relinked = SafeEntry::resolve(&named).unwrap().stat().unwrap();

            assert_eq!(bytes, b"original\n");
            assert_eq!(metadata.len(), bytes.len() as u64);
            assert!(!relinked.is_same_file_as(&metadata));
        }
    }

    /// Coverage for the identity check the authoring source reader applies to
    /// the descriptor it opens. A relink landing between the stat and the open
    /// cannot be scheduled from a test, so the check is exercised through its
    /// own seam with the two outcomes a reader can meet.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    mod relinked_entry {
        use super::*;
        use crate::safe_path::race_fixture::race_tree;

        /// The stat of the file the operator named, paired with the metadata of
        /// the descriptor a reader holds once that name reaches another regular
        /// file.
        fn stat_and_relinked_metadata() -> (EntryStat, fs::Metadata) {
            let tree = race_tree();
            let named = tree.named("registry.yaml");
            fs::write(&named, b"genuine\n").unwrap();
            let relinked = tree.outside("registry.yaml");
            fs::write(&relinked, b"decoy\n").unwrap();
            let stat = SafeEntry::resolve(&named).unwrap().stat().unwrap();
            let opened = fs::File::open(&relinked).unwrap().metadata().unwrap();
            (stat, opened)
        }

        /// The stat and the opened metadata of one file, which is what a read
        /// of an untouched source holds.
        fn stat_and_own_metadata() -> (EntryStat, fs::Metadata) {
            let tree = race_tree();
            let named = tree.named("registry.yaml");
            fs::write(&named, b"genuine\n").unwrap();
            let entry = SafeEntry::resolve(&named).unwrap();
            let stat = entry.stat().unwrap();
            let opened = entry.open_read().unwrap().metadata().unwrap();
            (stat, opened)
        }

        #[test]
        fn an_authoring_source_opened_as_another_file_is_refused() {
            let (stat, opened) = stat_and_relinked_metadata();

            let refused = ensure_source_entry_identity(stat, &opened, "registry.yaml")
                .expect_err("a descriptor that is not the stat'ed entry is refused");

            assert_eq!(refused.code, "source.file.invalid");
            assert_eq!(refused.path, "registry.yaml");
        }

        #[test]
        fn an_authoring_source_opened_as_the_stat_entry_is_read() {
            let (stat, opened) = stat_and_own_metadata();

            ensure_source_entry_identity(stat, &opened, "registry.yaml")
                .expect("the entry that was stat'ed is read");
        }
    }
}

#[cfg(test)]
#[test]
fn native_pattern_activation_diagnostics_preserve_field_and_pinned_target_recovery() {
    use registry_breg::migration::MigrationError;
    for (error, code, repair) in [
        (
            MigrationError::FieldPatternSyntax {
                entity_id: "person".to_owned(),
                field_id: "identifier".to_owned(),
            },
            "field.pattern.syntax_invalid",
            "restore the pre-activation backup",
        ),
        (
            MigrationError::FieldPatternExistingRows {
                entity_id: "person".to_owned(),
                field_id: "identifier".to_owned(),
            },
            "field.pattern.existing_rows_invalid",
            "retry the exact pinned target",
        ),
    ] {
        let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(error));
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(
            diagnostic.path,
            "entities[person].fields[identifier].pattern"
        );
        assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::ReconcileFailedMigration
        );
        assert!(diagnostic.message.contains("pinned in maintenance"));
        assert!(diagnostic.message.contains(repair));
        assert!(!diagnostic.message.contains("registry_data"));
    }
}

#[cfg(test)]
#[test]
fn apply_reports_an_empty_successor_plan_as_nothing_to_apply() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::EmptyPlan,
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.package.empty_plan");
    assert_eq!(diagnostic.path, "package");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::VerifiedPackage);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::CorrectPackageBuild
    );
    for fragment in [
        "nothing to apply",
        "keep the active package",
        "Nothing was changed",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
}

#[cfg(test)]
#[test]
fn apply_reports_a_refused_operator_reference_without_repeating_it() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::OperatorReference,
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.operator_reference.refused");
    assert_eq!(diagnostic.path, "operatorReference");
    for fragment in [
        "--operator-reference",
        "512 bytes",
        "keyed",
        "Nothing was changed",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
}

#[cfg(test)]
#[test]
fn apply_reports_a_history_coverage_refusal_with_its_recovery() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::HistoryCoverage,
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.history.coverage_incomplete");
    assert_eq!(diagnostic.path, "history");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::HistoryRebaseline);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::PrepareHistoryRebaselineRequest
    );
    for fragment in [
        "history coverage",
        "field-encryption erase-history",
        "history rebaseline",
        "https://docs.registrystack.org/operate/breg-retention/#restore-snapshot-coverage-after-an-erasure",
        "maintenance state was not changed",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
    assert!(!diagnostic.message.contains("reconciliation"));
}

#[cfg(test)]
#[test]
fn an_instance_claim_package_refusal_keeps_the_pin_sentence_it_names() {
    use registry_breg::instance_claim::InstanceClaimError;

    let sentence = "package.expectedDigest is sha256:a but the package at package.root is sha256:b; deploy the pinned package or update package.expectedDigest";
    let report = instance_claim_failure(
        "instance-claim status",
        InstanceClaimCliError::Claim(InstanceClaimError::PackageRefused(sentence.to_owned())),
    );
    assert!(!report.ok);
    assert_eq!(report.command, "instance-claim status");
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "instance_claim.package.refused");
    assert_eq!(diagnostic.path, "package");
    assert_eq!(diagnostic.message, sentence);
}

#[cfg(test)]
#[test]
fn an_active_package_pin_mismatch_names_both_digests() {
    let pin = || {
        PackageError::ExpectedDigestMismatch(PackageDigestMismatch {
            expected: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            found: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_owned(),
        })
    };
    let sentence = "package.expectedDigest is sha256:1111111111111111111111111111111111111111111111111111111111111111 but the package at package.root is sha256:2222222222222222222222222222222222222222222222222222222222222222; deploy the pinned package or update package.expectedDigest";
    for (report, command, code, path) in [
        (
            lifecycle_failure("apply", ApplyLifecycleError::CurrentPackage(pin())),
            "apply",
            "apply.package.refused",
            "package.root",
        ),
        (
            lifecycle_failure("plan", ApplyLifecycleError::CurrentPackage(pin())),
            "plan",
            "apply.package.refused",
            "package.root",
        ),
        (
            reconcile_lifecycle_failure(ReconcileLifecycleError::ActivePackage(pin())),
            "migration reconcile",
            "migration.reconcile.package.refused",
            "package",
        ),
        (
            history_erasure_lifecycle_failure(HistoryErasureLifecycleError::Package(pin())),
            "history erase",
            "history.erase.package.refused",
            "package",
        ),
        (
            history_rebaseline_lifecycle_failure(HistoryRebaselineLifecycleError::Package(pin())),
            "history rebaseline",
            "history.rebaseline.package.refused",
            "package",
        ),
        (
            field_encryption_preflight_failure(
                FieldEncryptionPreflightLifecycleError::PredecessorPackage(pin()),
            ),
            "field-encryption preflight",
            "field_encryption.preflight.predecessor_package.refused",
            "package",
        ),
        (
            field_encryption_erase_history_failure(
                FieldEncryptionEraseHistoryLifecycleError::ActivePackage(pin()),
            ),
            "field-encryption erase-history",
            "field_encryption.erase_history.package.refused",
            "package",
        ),
    ] {
        assert!(!report.ok);
        assert_eq!(report.command, command);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, path);
        assert_eq!(diagnostic.message, sentence, "{command}");
        assert_eq!(diagnostic.artifact, DiagnosticArtifact::VerifiedPackage);
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::VerifyPackageIntegrity
        );
    }
}

#[cfg(test)]
#[test]
fn apply_chain_refusals_name_the_operators_next_command() {
    use registry_breg::migration::MigrationError;

    for (error, code, path, next) in [
        (
            ApplyLifecycleError::Uninitialized,
            "apply.database.uninitialized",
            "database",
            "bregctl apply --initial",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::AlreadyActive),
            "apply.package.already_active",
            "package",
            "bregctl status",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::DatabaseMismatch),
            "apply.database.identity_mismatch",
            "identity.databaseId",
            "database.migrationUrlRef",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::PackageBinding),
            "apply.package.refused",
            "package",
            "bregctl package --baseline-package",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::UnrecognizedDatabase),
            "apply.database.unrecognized",
            "database",
            "upgrade one release at a time",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::RuntimeWriteAuthority(
                registry_breg::postgres::RuntimeWriteAuthority::Privilege {
                    grantee: "PUBLIC".to_owned(),
                    privilege: "CREATE".to_owned(),
                    object: "SCHEMA registry_data".to_owned(),
                },
            )),
            "apply.runtime_role.can_write",
            "database.roles.runtime",
            "`REVOKE CREATE ON SCHEMA registry_data FROM PUBLIC`, then rerun the refused command",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::ResumeRolesDiffer {
                role_mode: "split".to_owned(),
                runtime_role: "registry_runtime".to_owned(),
            }),
            "apply.resume.roles_differ",
            "database.roles",
            "runtime role `registry_runtime`; rerun the apply with the database roles it started with, or, for a new package, assess it with `bregctl migration reconcile`",
        ),
        (
            ApplyLifecycleError::Apply(MigrationError::SuccessorRolesDiffer {
                role_mode: "split".to_owned(),
                runtime_role: "registry_runtime".to_owned(),
            }),
            "apply.successor.roles_differ",
            "database.roles",
            "runtime role `registry_runtime`; apply the active package with the new roles first",
        ),
    ] {
        let report = apply_lifecycle_failure(error);
        assert!(!report.ok);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, path);
        assert!(
            diagnostic.message.contains(next),
            "{next}: {}",
            diagnostic.message
        );
        assert!(
            diagnostic.message.contains("Nothing was changed"),
            "{}",
            diagnostic.message
        );
    }
}

#[cfg(test)]
#[test]
fn apply_refuses_an_already_active_package_the_database_does_not_run() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::ActivePackageMismatch,
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.package.active_mismatch");
    assert_eq!(diagnostic.path, "package.root");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::PackageActivation);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::CorrectRuntimeConfiguration
    );
    for fragment in [
        "set package.root to the active package directory",
        "bregctl status",
        "migration reconcile",
        "never been activated, apply it with --initial",
        "Nothing was changed",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
}

#[cfg(test)]
#[test]
fn apply_reports_a_refused_statement_with_its_sqlstate_and_objects() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::StatementFailed(
            registry_breg::postgres::PostgresFailure {
                sqlstate: Some("23502".to_owned()),
                table: Some("asset_table".to_owned()),
                column: Some("rank_column".to_owned()),
                constraint: None,
            },
        ),
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.migration.statement_failed");
    assert_eq!(diagnostic.path, "database");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::ReconcileFailedMigration
    );
    for fragment in [
        "SQLSTATE 23502 (integrity constraint violation), table asset_table, column rank_column",
        "pinned in maintenance",
        "retry the same target",
        "migration reconcile",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
}

#[cfg(test)]
#[test]
fn apply_reports_an_unavailable_database_before_maintenance_as_retryable() {
    let report = apply_lifecycle_failure(ApplyLifecycleError::Apply(
        registry_breg::migration::MigrationError::DatabaseUnavailable,
    ));
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "apply.database.unavailable");
    assert_eq!(diagnostic.path, "database");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::VerifyMigrationAuthority
    );
    for fragment in [
        "before maintenance began",
        "Nothing was changed",
        "Retry the same apply once the database is reachable",
    ] {
        assert!(
            diagnostic.message.contains(fragment),
            "{fragment}: {}",
            diagnostic.message
        );
    }
    assert!(
        !diagnostic.message.contains("reconciliation"),
        "{}",
        diagnostic.message
    );
}

/// A held migration lock has its own `apply.database.in_progress` code for
/// `apply` and `plan` alike: its sentence names the session holding the
/// lock, and neither it nor its suggested action sends the operator to check
/// that the database is reachable.
#[cfg(test)]
#[test]
fn apply_reports_a_held_migration_lock_as_an_activation_in_progress() {
    for command in ["apply", "plan"] {
        let report = lifecycle_failure(
            command,
            ApplyLifecycleError::Apply(registry_breg::migration::MigrationError::MigrationLockHeld),
        );
        assert_eq!(report.command, command);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, "apply.database.in_progress");
        assert_eq!(diagnostic.path, "database");
        assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::RetryAfterMigrationLockReleases
        );
        for fragment in [
            "another session held the exclusive migration lock",
            "before maintenance began",
            "Nothing was changed",
            "Retry the same apply once it releases",
        ] {
            assert!(
                diagnostic.message.contains(fragment),
                "{fragment}: {}",
                diagnostic.message
            );
        }
        for fragment in ["reachable", "migrationUrlRef", "reconciliation"] {
            assert!(
                !diagnostic.message.contains(fragment),
                "{fragment}: {}",
                diagnostic.message
            );
        }
    }
}

#[cfg(test)]
#[test]
fn an_active_registry_read_reports_a_held_migration_lock_as_in_progress() {
    for (command, prefix) in [
        ("history erase", "history.erase"),
        ("history rebaseline", "history.rebaseline"),
        ("migration reconcile", "migration.reconcile"),
    ] {
        let report = active_registry_failure(command, prefix, ActiveRegistryError::InProgress);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(
            diagnostic.code,
            format!("{prefix}.active_registry.in_progress")
        );
        assert_eq!(diagnostic.path, "database");
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::RetryAfterMigrationLockReleases
        );
        assert!(
            diagnostic
                .message
                .contains("another session holds the exclusive migration lock"),
            "{}",
            diagnostic.message
        );
        assert!(
            !diagnostic.message.contains("migrationUrlRef"),
            "{}",
            diagnostic.message
        );
    }
}

/// A migration lock held when an operator maintenance transaction takes it
/// has its own `in_progress` code for each command, with the wait-and-retry
/// action, and is never reported as unavailable storage.
#[cfg(test)]
#[test]
fn operator_maintenance_reports_a_held_migration_lock_as_in_progress() {
    use registry_breg::import_authority::ImportAuthorityError;
    use registry_breg::instance_claim::InstanceClaimError;
    use registry_breg::mutation::MutationError;

    for (report, command, code) in [
        (
            evidence_retention_failure(MutationError::MigrationLockHeld),
            "evidence-retention erase-expired",
            "evidence_retention.in_progress",
        ),
        (
            request_retention_failure(
                "request-retention erase",
                RequestRetentionCliError::MigrationLockHeld,
            ),
            "request-retention erase",
            "request_retention.in_progress",
        ),
        (
            import_authority_failure(
                "import-authority open",
                ImportAuthorityCliError::Authority(ImportAuthorityError::MigrationLockHeld),
            ),
            "import-authority open",
            "import_authority.in_progress",
        ),
        (
            instance_claim_failure(
                "instance-claim adopt",
                InstanceClaimCliError::Claim(InstanceClaimError::MigrationLockHeld),
            ),
            "instance-claim adopt",
            "instance_claim.in_progress",
        ),
    ] {
        assert_eq!(report.command, command);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, "database");
        assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::RetryAfterMigrationLockReleases,
            "{code}"
        );
        assert!(
            diagnostic
                .message
                .contains("another session held the exclusive migration lock"),
            "{code}: {}",
            diagnostic.message
        );
        for fragment in ["unavailable", "migrationUrlRef"] {
            assert!(
                !diagnostic.message.contains(fragment),
                "{code} {fragment}: {}",
                diagnostic.message
            );
        }
    }
    let unavailable = evidence_retention_failure(MutationError::Unavailable);
    assert_eq!(
        unavailable.diagnostics[0].code,
        "evidence_retention.unavailable"
    );
}

/// A migration lock held when a history maintenance transaction takes it has
/// its own `in_progress` code for each command, with the wait-and-retry
/// action, and is never reported as unavailable storage.
#[cfg(test)]
#[test]
fn history_maintenance_reports_a_held_migration_lock_as_in_progress() {
    use registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureError;
    use registry_breg::history_erasure::HistoryErasureError;
    use registry_breg::history_rebaseline::HistoryRebaselineError;

    for (report, command, code) in [
        (
            history_erasure_lifecycle_failure(HistoryErasureLifecycleError::Erasure(
                HistoryErasureError::MigrationLockHeld,
            )),
            "history erase",
            "history.erase.in_progress",
        ),
        (
            history_rebaseline_lifecycle_failure(HistoryRebaselineLifecycleError::Rebaseline(
                HistoryRebaselineError::MigrationLockHeld,
            )),
            "history rebaseline",
            "history.rebaseline.in_progress",
        ),
        (
            field_encryption_erase_history_failure(
                FieldEncryptionEraseHistoryLifecycleError::Erase(
                    FieldEncryptionHistoryErasureError::MigrationLockHeld,
                ),
            ),
            "field-encryption erase-history",
            "field_encryption.erase_history.in_progress",
        ),
        (
            field_encryption_erase_history_failure(
                FieldEncryptionEraseHistoryLifecycleError::Erase(
                    FieldEncryptionHistoryErasureError::Erasure(
                        HistoryErasureError::MigrationLockHeld,
                    ),
                ),
            ),
            "field-encryption erase-history",
            "field_encryption.erase_history.in_progress",
        ),
        (
            field_encryption_erase_history_failure(
                FieldEncryptionEraseHistoryLifecycleError::Erase(
                    FieldEncryptionHistoryErasureError::Rebaseline(
                        HistoryRebaselineError::MigrationLockHeld,
                    ),
                ),
            ),
            "field-encryption erase-history",
            "field_encryption.erase_history.in_progress",
        ),
    ] {
        assert_eq!(report.command, command);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, "database");
        assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::RetryAfterMigrationLockReleases,
            "{code}"
        );
        assert!(
            diagnostic
                .message
                .contains("another session held the exclusive migration lock"),
            "{code}: {}",
            diagnostic.message
        );
        for fragment in ["unavailable", "migrationUrlRef"] {
            assert!(
                !diagnostic.message.contains(fragment),
                "{code} {fragment}: {}",
                diagnostic.message
            );
        }
    }
}

#[cfg(test)]
#[test]
fn apply_reports_actionable_field_encryption_provider_failures() {
    for (error, code, message_fragment) in [
        (
            ApplyLifecycleError::FieldEncryptionConfiguration,
            "apply.field_encryption.configuration_refused",
            "provider is required",
        ),
        (
            ApplyLifecycleError::FieldEncryptionCustody,
            "apply.field_encryption.custody_refused",
            "only for local database initialization",
        ),
    ] {
        let report = apply_lifecycle_failure(error);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, code);
        assert_eq!(diagnostic.path, "fieldEncryption.provider");
        assert_eq!(
            diagnostic.artifact,
            DiagnosticArtifact::RuntimeConfiguration
        );
        assert_eq!(
            diagnostic.suggested_action,
            SuggestedAction::CorrectRuntimeConfiguration
        );
        assert!(diagnostic.message.contains(message_fragment));
    }
}

#[cfg(test)]
#[test]
fn native_pattern_schema_test_diagnostic_identifies_only_the_authored_field() {
    let report = test_lifecycle_failure(TestLifecycleError::FieldPatternSyntax {
        entity_id: "person".to_owned(),
        field_id: "identifier".to_owned(),
    });
    assert_eq!(report.diagnostics.len(), 1);
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "field.pattern.syntax_invalid");
    assert_eq!(
        diagnostic.path,
        "entities[person].fields[identifier].pattern"
    );
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::SchemaTestCandidate);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::CorrectSchemaTestCandidate
    );
    assert!(!diagnostic.message.contains("registry_data"));
    assert!(diagnostic.message.contains("PostgreSQL ARE syntax"));
}

#[cfg(test)]
#[test]
fn review_fingerprint_mismatch_names_the_declared_and_the_measured_fingerprint() {
    let declared = format!("sha256:{}", "a".repeat(64));
    let measured = format!("sha256:{}", "b".repeat(64));
    let report = test_lifecycle_failure(TestLifecycleError::ReviewFingerprint {
        declared: declared.clone(),
        measured: measured.clone(),
    });
    assert_eq!(report.diagnostics.len(), 1);
    let diagnostic = &report.diagnostics[0];
    assert_eq!(diagnostic.code, "migration.review.fingerprint_mismatch");
    assert_eq!(diagnostic.path, "reviewedMigrations");
    assert_eq!(diagnostic.artifact, DiagnosticArtifact::DatabaseMigration);
    assert_eq!(
        diagnostic.suggested_action,
        SuggestedAction::CorrectPackageBuild
    );
    assert!(diagnostic.message.contains(&declared));
    assert!(diagnostic.message.contains(&measured));
    assert!(diagnostic.message.contains("--fingerprint-only"));
}

#[cfg(test)]
#[test]
fn help_requested_matches_bare_help_only_in_the_subcommand_position() {
    fn args(tokens: &[&str]) -> Vec<OsString> {
        std::iter::once("bregctl")
            .chain(tokens.iter().copied())
            .map(OsString::from)
            .collect()
    }

    for tokens in [
        &["help"][..],
        &["help", "--format", "json"][..],
        &["--format", "json", "help"][..],
        &["--format", "json", "--help"][..],
        &["--format", "json", "-h"][..],
        &["--format", "json", "project", "--help"][..],
    ] {
        assert!(
            help_requested(&args(tokens)),
            "{tokens:?} must be recognized as a help request"
        );
    }

    for tokens in [
        &["--format", "json", "explain", "access", "help"][..],
        &["--format", "json", "doctor", "--runtime-config", "help"][..],
        &["explain", "access", "help"][..],
    ] {
        assert!(
            !help_requested(&args(tokens)),
            "{tokens:?} carries `help` as a value, not the subcommand"
        );
    }
}

#[cfg(all(test, unix))]
mod field_encryption_keygen_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn keygen_arguments(output: &Path) -> Vec<OsString> {
        vec![
            OsString::from("bregctl"),
            OsString::from("field-encryption"),
            OsString::from("keygen"),
            OsString::from("--output"),
            output.to_owned().into_os_string(),
        ]
    }

    /// The rendering a pipe or captured transcript receives, ANSI-stripped the
    /// way `main_entry` strips it for anything that is not a terminal.
    fn plain(rendered: &[u8]) -> String {
        let rendered = String::from_utf8(rendered.to_vec()).expect("output is UTF-8");
        anstream::adapter::strip_str(&rendered).to_string()
    }

    #[test]
    fn keygen_writes_an_owner_only_base64_key_it_never_prints() {
        let directory = tempfile::tempdir().expect("test directory creates");
        let output = directory.path().join("secrets").join("breg-field-dek");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_from(keygen_arguments(&output), &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let rendered = plain(&stdout);
        assert!(
            rendered.contains("Wrote one base64 field data key."),
            "{rendered}"
        );

        let metadata = fs::metadata(&output).expect("the data key file exists");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let parent =
            fs::metadata(directory.path().join("secrets")).expect("the created parent exists");
        assert_eq!(parent.permissions().mode() & 0o777, 0o700);

        let contents = fs::read_to_string(&output).expect("the data key file reads");
        let decoded = STANDARD
            .decode(contents.trim_ascii())
            .expect("the data key file is base64");
        assert_eq!(
            decoded.len(),
            32,
            "the data key decodes to exactly 32 bytes"
        );
        assert!(
            !rendered.contains(contents.trim_ascii()),
            "the data key never reaches standard output"
        );
    }

    #[test]
    fn keygen_refuses_an_existing_output_without_touching_it() {
        let directory = tempfile::tempdir().expect("test directory creates");
        let output = directory.path().join("breg-field-dek");
        const EXISTING: &str = "existing-key-material-canary";
        fs::write(&output, EXISTING).expect("the existing output writes");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_from(keygen_arguments(&output), &mut stdout, &mut stderr),
            ExitCode::from(DOMAIN_REFUSAL_EXIT)
        );
        let rendered = plain(&stderr);
        assert!(
            rendered.contains("field_encryption.keygen.output_exists"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(EXISTING),
            "the refusal never echoes the existing file's contents"
        );
        assert_eq!(
            fs::read_to_string(&output).expect("the existing file reads"),
            EXISTING,
            "an existing data key file is never overwritten"
        );
    }

    #[test]
    fn keygen_names_its_destination_only_with_output() {
        assert!(Cli::try_parse_from(keygen_arguments(Path::new("/dek"))).is_ok());
        assert!(
            Cli::try_parse_from(["bregctl", "field-encryption", "keygen", "--out", "/dek"])
                .is_err()
        );
    }

    #[test]
    fn keygen_refuses_a_relative_output_path() {
        let directory = tempfile::tempdir().expect("test directory creates");
        let relative = Path::new("breg-field-dek");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_from(keygen_arguments(relative), &mut stdout, &mut stderr),
            ExitCode::from(DOMAIN_REFUSAL_EXIT)
        );
        assert!(plain(&stderr).contains("field_encryption.keygen.path_invalid"));
        assert!(
            !directory.path().join("breg-field-dek").exists(),
            "a refused relative path writes nothing"
        );
    }

    #[test]
    fn keygen_reports_the_machine_shape_without_the_key() {
        let directory = tempfile::tempdir().expect("test directory creates");
        let output = directory.path().join("machine-dek");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut arguments = keygen_arguments(&output);
        arguments.insert(1, OsString::from("--format"));
        arguments.insert(2, OsString::from("json"));
        assert_eq!(
            run_from(arguments, &mut stdout, &mut stderr),
            ExitCode::SUCCESS
        );
        assert!(stderr.is_empty());
        let rendered = String::from_utf8(stdout.clone()).expect("json is UTF-8");
        let value: Value = serde_json::from_str(rendered.trim_end()).expect("report is JSON");
        assert_eq!(value["ok"], json!(true));
        assert_eq!(value["command"], json!("field-encryption keygen"));
        assert_eq!(value["output"], json!(output.display().to_string()));

        let contents = fs::read_to_string(&output).expect("the data key file reads");
        assert!(
            !rendered.contains(contents.trim_ascii()),
            "the data key never reaches the machine report"
        );
    }
}

#[cfg(test)]
mod field_encryption_lifecycle_cli_tests {
    use super::*;

    #[test]
    fn field_encryption_preflight_takes_only_the_runtime_config_and_package() {
        let parsed = Cli::try_parse_from([
            "bregctl",
            "field-encryption",
            "preflight",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--package",
            "/tmp/successor-package",
        ])
        .expect("field-encryption preflight parses");
        let Command::FieldEncryption(args) = parsed.command else {
            panic!("field-encryption command parsed");
        };
        let FieldEncryptionCommand::Preflight(args) = args.command else {
            panic!("field-encryption preflight command parsed");
        };
        assert_eq!(args.runtime_config, PathBuf::from("/tmp/runtime.yaml"));
        assert_eq!(args.package, PathBuf::from("/tmp/successor-package"));
        // The preflight names no records: its scope is the plan itself, and a
        // request file belongs to the erase-history command alone.
        assert!(Cli::try_parse_from([
            "bregctl",
            "field-encryption",
            "preflight",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--package",
            "/tmp/successor-package",
            "--request-file",
            "/tmp/request.json",
        ])
        .is_err());
    }

    #[test]
    fn field_encryption_erase_history_requires_request_file_not_inline_targets() {
        let parsed = Cli::try_parse_from([
            "bregctl",
            "field-encryption",
            "erase-history",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--request-file",
            "/tmp/request.json",
        ])
        .expect("field-encryption erase-history parses");
        let Command::FieldEncryption(args) = parsed.command else {
            panic!("field-encryption command parsed");
        };
        let FieldEncryptionCommand::EraseHistory(args) = args.command else {
            panic!("field-encryption erase-history command parsed");
        };
        assert_eq!(args.runtime_config, PathBuf::from("/tmp/runtime.yaml"));
        assert_eq!(args.request_file, PathBuf::from("/tmp/request.json"));
        assert!(Cli::try_parse_from([
            "bregctl",
            "field-encryption",
            "erase-history",
            "--runtime-config",
            "/tmp/runtime.yaml",
            "--record-id",
            "018feaa0-68f9-4a45-b9e3-58436df07af7",
        ])
        .is_err());
    }

    fn sample_preflight_report() -> FieldEncryptionPreflightSuccessReport {
        FieldEncryptionPreflightSuccessReport {
            ok: true,
            command: "field-encryption preflight",
            outcome: FieldEncryptionPreflightLifecycleOutcome {
                package_digest: "pkg-1".to_owned(),
                report: registry_breg::field_encryption_backfill::FieldEncryptionBackfillPreflightReport {
                    steps: vec![
                        registry_breg::field_encryption_backfill::FieldEncryptionBackfillStepPreflight {
                            entity_id: "membership".to_owned(),
                            history_choice:
                                registry_breg::migration_plan::ReviewedFieldEncryptionHistory::EraseAndRebaseline,
                            fields: vec![
                                registry_breg::field_encryption_backfill::FieldEncryptionBackfillFieldPreflight {
                                    field_id: "secret".to_owned(),
                                    api_name: "secret".to_owned(),
                                    unique_blind_index: true,
                                    plaintext_row_count: 3,
                                    journal_row_count: 5,
                                    request_target_row_count: 2,
                                    request_proposal_row_count: 1,
                                    idempotency_row_count: 1,
                                    outbox_row_count: 1,
                                    duplicate_record_ids: vec![
                                        "018feaa0-68f9-4a45-b9e3-58436df07af7".to_owned(),
                                    ],
                                },
                            ],
                        },
                    ],
                },
            },
        }
    }

    #[test]
    fn field_encryption_preflight_report_carries_counts_and_record_names_only() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_field_encryption_preflight_success(
                &sample_preflight_report(),
                OutputFormat::Json,
                &mut stdout,
                &mut stderr,
            ),
            ExitCode::SUCCESS
        );
        let rendered = String::from_utf8(stdout).expect("json is UTF-8");
        assert!(rendered.contains("\"command\": \"field-encryption preflight\""));
        assert!(rendered.contains("\"historyChoice\": \"erase-and-rebaseline\""));
        assert!(rendered.contains("\"plaintextRowCount\": 3"));
        assert!(rendered.contains("\"duplicateRecordIds\": ["));
        // Record identifiers are authored identifiers and are named by design;
        // neither the human nor machine rendering carries anything else.
        assert!(rendered.contains("018feaa0-68f9-4a45-b9e3-58436df07af7"));
        assert!(!rendered.to_lowercase().contains("operator"));
        assert!(!rendered.to_lowercase().contains("reason"));

        let mut plain_stdout = Vec::new();
        let mut plain_stderr = Vec::new();
        assert_eq!(
            write_field_encryption_preflight_success(
                &sample_preflight_report(),
                OutputFormat::Human,
                &mut plain_stdout,
                &mut plain_stderr,
            ),
            ExitCode::SUCCESS
        );
        let rendered = String::from_utf8(plain_stdout).expect("plain output is UTF-8");
        assert!(rendered.contains("erase-and-rebaseline"));
        assert!(rendered.contains("3 plaintext"));
    }

    #[test]
    fn field_encryption_erase_history_report_is_value_free() {
        let report = FieldEncryptionEraseHistorySuccessReport {
            ok: true,
            command: "field-encryption erase-history",
            outcome: FieldEncryptionEraseHistoryLifecycleOutcome {
                package_digest: "pkg-1".to_owned(),
                outcome:
                    registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureOutcome {
                        erased_record_count: 2,
                        erased_revision_count: 4,
                        erased_commit_member_count: 2,
                        scrubbed_change_context_count: 1,
                        scrubbed_outbox_payload_count: 1,
                        scrubbed_cached_response_count: 1,
                        scrubbed_request_target_count: 2,
                        scrubbed_request_proposal_count: 1,
                        removed_descriptor_count: 0,
                        rebaseline: registry_breg::history_rebaseline::HistoryRebaselineOutcome {
                            baseline_position: 3,
                            verified_entity_count: 1,
                            verified_record_count: 2,
                            previous_coverage_baseline_position: 0,
                            previous_unavailable_after_position: Some(1),
                        },
                    },
            },
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_field_encryption_erase_history_success(
                &report,
                OutputFormat::Json,
                &mut stdout,
                &mut stderr,
            ),
            ExitCode::SUCCESS
        );
        let rendered = String::from_utf8(stdout).expect("json is UTF-8");
        assert!(rendered.contains("\"command\": \"field-encryption erase-history\""));
        assert!(rendered.contains("\"scrubbedRequestTargetCount\": 2"));
        assert!(rendered.contains("\"baselinePosition\": 3"));
        assert!(!rendered.to_lowercase().contains("operator"));
        assert!(!rendered.to_lowercase().contains("reason"));
    }
}
