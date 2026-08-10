// SPDX-License-Identifier: Apache-2.0
//! Shared authoring facade used verbatim by `relayctl`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::{ChainState, JsonlFileSink};
use registry_platform_sqlite::{
    inspect_schema as inspect_sqlite_schema, materialize_fixture, CapturedSnapshot,
    DatabaseProfile, SchemaObjectKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::{generate_artifacts, ArtifactSet};
use crate::audit::RelayAudit;
use crate::compiler::{
    classification_inventory_digest, compile_contract_with_governed_files,
    referenced_governed_files, GovernedFileSet,
};
use crate::contract::{ClassificationReviewDocument, RegistryContract, RelayRuntime};
use crate::cursor::CursorKey;
use crate::diff::{diff_registries, ChangeImpactReport};
use crate::fixtures::{
    execute_fixture_journey, fixture_authenticator, parse_journey, FixturePlanReport,
};
use crate::identification::{
    classification_inventory_report, classification_review_starter, contextual_review_findings,
    identify_contract, operation_explanation, render_classification_inventory_report,
    render_classification_review_yaml, render_contextual_review_findings,
    render_identification_report, render_operation_explanation, OperationExplanation,
    CLASSIFICATION_INVENTORY_REPORT_PATH, CLASSIFICATION_REVIEW_STARTER_PATH,
    CONTEXTUAL_REVIEW_FINDINGS_PATH, IDENTIFICATION_REPORT_PATH, OPERATION_EXPLANATION_PATH,
};
use crate::model::{
    CompileProfile, CompileReport, CompiledRegistry, Diagnostic, DiagnosticSeverity,
};
use crate::package::{build_package, PackageManifest};
use crate::server::{
    router, AlignmentMetadata, InstitutionMetadata, QuotaConfig, RelayService, ServiceMetadata,
};
use crate::source_observation::{inspection_limits, observe_sources};
use crate::sqlite_runtime::{RuntimeSourceBinding, SqliteRuntime, SqliteRuntimeLimits};

#[derive(Clone, Debug)]
pub struct InitOptions {
    pub project_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct InspectOptions {
    pub database_path: PathBuf,
    pub starter_output: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub project_root: PathBuf,
    pub production: bool,
    pub explain: bool,
}

#[derive(Clone, Debug)]
pub struct GenerateOptions {
    pub project_root: PathBuf,
    pub output_dir: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct TestOptions {
    pub project_root: PathBuf,
    pub fixture_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DiffOptions {
    pub previous_root: PathBuf,
    pub current_root: PathBuf,
}

#[derive(Clone, Debug)]
pub struct PackageOptions {
    pub project_root: PathBuf,
    pub output_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolingStatus {
    Success,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolingReport {
    pub status: ToolingStatus,
    pub diagnostics: Vec<Diagnostic>,
    pub details: ToolingDetails,
}

impl ToolingReport {
    pub fn is_success(&self) -> bool {
        self.status == ToolingStatus::Success
    }

    fn success(details: ToolingDetails) -> Self {
        Self {
            status: ToolingStatus::Success,
            diagnostics: Vec::new(),
            details,
        }
    }

    fn refused(diagnostics: Vec<Diagnostic>, details: ToolingDetails) -> Self {
        Self {
            status: ToolingStatus::Refused,
            diagnostics,
            details,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ToolingDetails {
    Initialized {
        files: Vec<String>,
    },
    SchemaInspection {
        fingerprint: String,
        objects: Vec<InspectedObject>,
        starter_file: Option<String>,
    },
    Check {
        contract_revision: Option<String>,
        production: bool,
        configuration_key_paths: Option<ConfigurationKeyPaths>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation_explanation: Option<OperationExplanation>,
    },
    Generate {
        contract_revision: Option<String>,
        artifacts: Vec<GeneratedFile>,
    },
    Test {
        contract_revision: Option<String>,
        report: Option<FixturePlanReport>,
    },
    Diff {
        report: Option<ChangeImpactReport>,
    },
    Package {
        manifest: Option<PackageManifest>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConfigurationKeyPaths {
    pub registry: Vec<String>,
    pub runtime: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InspectedObject {
    pub kind: InspectedObjectKind,
    pub name: String,
    pub table_name: String,
    pub columns: Vec<InspectedColumn>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InspectedObjectKind {
    Table,
    Index,
    View,
    Trigger,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InspectedColumn {
    pub name: String,
    pub declared_type: String,
    pub nullable: bool,
    pub primary_key: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedFile {
    pub id: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum ToolingError {
    #[error("the requested authoring input could not be read")]
    Read,
    #[error("the requested authoring output could not be written")]
    Write,
    #[error("the requested path is unsafe")]
    UnsafePath,
    #[error("the SQLite schema could not be inspected")]
    Inspect,
    #[error("the generated artifacts could not be constructed")]
    Generate,
    #[error("the authoring explanation could not be constructed")]
    Explain,
    #[error("the deployment package could not be constructed")]
    Package,
}

impl ToolingError {
    /// A deliberately categorical message containing no source value or
    /// absolute filesystem path.
    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::Read => "the requested authoring input could not be read",
            Self::Write => "the requested authoring output could not be written",
            Self::UnsafePath => "the requested path is unsafe",
            Self::Inspect => "the SQLite schema could not be inspected",
            Self::Generate => "the generated artifacts could not be constructed",
            Self::Explain => "the authoring explanation could not be constructed",
            Self::Package => "the deployment package could not be constructed",
        }
    }
}

pub fn init_project(options: &InitOptions) -> Result<ToolingReport, ToolingError> {
    if options.project_root.exists() {
        if fs::symlink_metadata(&options.project_root)
            .map_err(|_| ToolingError::Read)?
            .file_type()
            .is_symlink()
        {
            return Err(ToolingError::UnsafePath);
        }
        let mut entries = fs::read_dir(&options.project_root).map_err(|_| ToolingError::Read)?;
        if entries.next().is_some() {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "project.destination_not_empty",
                    ".",
                    "initialization requires a new or empty project directory",
                )],
                ToolingDetails::Initialized { files: Vec::new() },
            ));
        }
    } else {
        fs::create_dir(&options.project_root).map_err(|_| ToolingError::Write)?;
    }
    let files = [
        ("registry.yaml", STARTER_REGISTRY),
        ("runtime.yaml", STARTER_RUNTIME),
        ("governance/identifier-lifecycle.yaml", STARTER_LIFECYCLE),
        (
            "governance/classification-review.yaml",
            STARTER_CLASSIFICATION,
        ),
        ("governance/legal-basis.yaml", STARTER_LEGAL_BASIS),
        ("governance/processing.dpv.yaml", STARTER_PROCESSING),
        ("codelists/record-lifecycle.yaml", STARTER_CODELIST),
    ];
    for (relative, content) in &files {
        write_relative_new(&options.project_root, relative, content.as_bytes())?;
    }
    Ok(ToolingReport::success(ToolingDetails::Initialized {
        files: files.iter().map(|(path, _)| (*path).to_owned()).collect(),
    }))
}

pub fn inspect_schema(options: &InspectOptions) -> Result<ToolingReport, ToolingError> {
    let snapshot =
        CapturedSnapshot::capture(&options.database_path).map_err(|_| ToolingError::Inspect)?;
    let catalog = inspect_sqlite_schema(&DatabaseProfile::Snapshot(snapshot), &inspection_limits())
        .map_err(|_| ToolingError::Inspect)?;
    let objects = catalog
        .objects
        .iter()
        .map(|object| InspectedObject {
            kind: inspected_kind(object.kind),
            name: object.name.clone(),
            table_name: object.table_name.clone(),
            columns: object
                .columns
                .iter()
                .map(|column| InspectedColumn {
                    name: column.name.clone(),
                    declared_type: column.declared_type.clone(),
                    nullable: column.nullable,
                    primary_key: column.primary_key,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let starter_file = if let Some(output) = &options.starter_output {
        if output.exists()
            && fs::symlink_metadata(output)
                .map_err(|_| ToolingError::Read)?
                .file_type()
                .is_symlink()
        {
            return Err(ToolingError::UnsafePath);
        }
        fs::create_dir_all(output).map_err(|_| ToolingError::Write)?;
        let starter = serde_norway::to_string(&SchemaStarter {
            schema_fingerprint: &catalog.fingerprint,
            review_status: "suggested",
            objects: &objects,
        })
        .map_err(|_| ToolingError::Write)?;
        let path = output.join("schema-starter.yaml");
        fs::write(&path, starter).map_err(|_| ToolingError::Write)?;
        Some("schema-starter.yaml".into())
    } else {
        None
    };
    Ok(ToolingReport::success(ToolingDetails::SchemaInspection {
        fingerprint: catalog.fingerprint,
        objects,
        starter_file,
    }))
}

pub fn check_project(options: &CheckOptions) -> Result<ToolingReport, ToolingError> {
    match compile_project(
        &options.project_root,
        if options.production {
            CompileProfile::Production
        } else {
            CompileProfile::Authoring
        },
    )? {
        ProjectCompilation::Compiled(project) => {
            let operation_explanation = if options.explain {
                let classification_digest = classification_inventory_digest(&project.registry)
                    .map_err(|_| ToolingError::Explain)?;
                Some(
                    operation_explanation(&project.registry, &classification_digest)
                        .map_err(|_| ToolingError::Explain)?,
                )
            } else {
                None
            };
            let configuration_key_paths = ConfigurationKeyPaths {
                registry: collect_configuration_key_paths(
                    &serde_json::to_value(&project.contract).map_err(|_| ToolingError::Inspect)?,
                ),
                runtime: project
                    .runtime
                    .as_ref()
                    .map(|runtime| serde_json::to_value(runtime).map_err(|_| ToolingError::Inspect))
                    .transpose()?
                    .as_ref()
                    .map(collect_configuration_key_paths)
                    .unwrap_or_default(),
            };
            Ok(ToolingReport::success(ToolingDetails::Check {
                contract_revision: Some(project.registry.contract_revision),
                production: options.production,
                configuration_key_paths: Some(configuration_key_paths),
                operation_explanation,
            }))
        }
        ProjectCompilation::Refused(report) => Ok(ToolingReport::refused(
            report.diagnostics,
            ToolingDetails::Check {
                contract_revision: None,
                production: options.production,
                configuration_key_paths: None,
                operation_explanation: None,
            },
        )),
    }
}

fn collect_configuration_key_paths(document: &serde_json::Value) -> Vec<String> {
    fn walk(value: &serde_json::Value, prefix: &str, paths: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(values) => {
                let dynamic_map = matches!(
                    prefix,
                    "sources"
                        | "resources[].sourceColumnClassifications"
                        | "resources[].properties"
                        | "resources[].disclosureProfiles"
                        | "resources[].operations.lookups[].requestBody.selectors"
                );
                if dynamic_map {
                    let wildcard = format!("{prefix}.*");
                    paths.insert(wildcard.clone());
                    for child in values.values() {
                        walk(child, &wildcard, paths);
                    }
                } else {
                    for (name, child) in values {
                        let path = if prefix.is_empty() {
                            name.clone()
                        } else {
                            format!("{prefix}.{name}")
                        };
                        paths.insert(path.clone());
                        walk(child, &path, paths);
                    }
                }
            }
            serde_json::Value::Array(values) => {
                let path = format!("{prefix}[]");
                paths.insert(path.clone());
                for child in values {
                    walk(child, &path, paths);
                }
            }
            _ => {}
        }
    }

    let mut paths = BTreeSet::new();
    walk(document, "", &mut paths);
    paths.into_iter().collect()
}

pub fn generate_project(options: &GenerateOptions) -> Result<ToolingReport, ToolingError> {
    let compilation = compile_project(&options.project_root, CompileProfile::Authoring)?;
    let project = match compilation {
        ProjectCompilation::Compiled(project) => project,
        ProjectCompilation::Refused(report) => {
            return Ok(ToolingReport::refused(
                report.diagnostics,
                ToolingDetails::Generate {
                    contract_revision: None,
                    artifacts: Vec::new(),
                },
            ));
        }
    };
    let CompiledProject {
        contract,
        registry,
        observed,
        ..
    } = *project;
    let artifacts = generate_artifacts(&registry).map_err(|_| ToolingError::Generate)?;
    let classification_digest =
        classification_inventory_digest(&registry).map_err(|_| ToolingError::Generate)?;
    let identification =
        identify_contract(&contract, &observed).map_err(|_| ToolingError::Generate)?;
    let inventory = classification_inventory_report(&registry, &classification_digest)
        .map_err(|_| ToolingError::Generate)?;
    let operation_explanation = operation_explanation(&registry, &classification_digest)
        .map_err(|_| ToolingError::Generate)?;
    let findings = contextual_review_findings(&registry, &classification_digest)
        .map_err(|_| ToolingError::Generate)?;
    let starter = classification_review_starter(&contract, &classification_digest, &identification)
        .map_err(|_| ToolingError::Generate)?;
    let authoring_outputs = [
        (
            "identification-report",
            IDENTIFICATION_REPORT_PATH,
            render_identification_report(&identification).map_err(|_| ToolingError::Generate)?,
        ),
        (
            "classification-inventory",
            CLASSIFICATION_INVENTORY_REPORT_PATH,
            render_classification_inventory_report(&inventory)
                .map_err(|_| ToolingError::Generate)?,
        ),
        (
            "operation-explanation",
            OPERATION_EXPLANATION_PATH,
            render_operation_explanation(&operation_explanation)
                .map_err(|_| ToolingError::Generate)?,
        ),
        (
            "contextual-review-findings",
            CONTEXTUAL_REVIEW_FINDINGS_PATH,
            render_contextual_review_findings(&findings).map_err(|_| ToolingError::Generate)?,
        ),
        (
            "classification-review-starter",
            CLASSIFICATION_REVIEW_STARTER_PATH,
            render_classification_review_yaml(&starter).map_err(|_| ToolingError::Generate)?,
        ),
    ];
    let output = options
        .output_dir
        .clone()
        .unwrap_or_else(|| options.project_root.join("generated"));
    write_artifacts(&output, &artifacts)?;
    let mut generated = artifacts
        .artifacts
        .iter()
        .map(|artifact| GeneratedFile {
            id: artifact.id.clone(),
            path: artifact.path.clone(),
            sha256: artifact.sha256.clone(),
        })
        .collect::<Vec<_>>();
    for (id, path, content) in authoring_outputs {
        write_generated_relative(&output, path, &content)?;
        generated.push(GeneratedFile {
            id: id.into(),
            path: path.into(),
            sha256: format!("sha256:{}", hex::encode(Sha256::digest(&content))),
        });
    }
    generated.sort_by(|left, right| left.path.cmp(&right.path).then(left.id.cmp(&right.id)));
    Ok(ToolingReport::success(ToolingDetails::Generate {
        contract_revision: Some(registry.contract_revision),
        artifacts: generated,
    }))
}

pub fn test_project(options: &TestOptions) -> Result<ToolingReport, ToolingError> {
    let compilation = compile_project(&options.project_root, CompileProfile::Authoring)?;
    let project = match compilation {
        ProjectCompilation::Compiled(project) => project,
        ProjectCompilation::Refused(report) => {
            return Ok(ToolingReport::refused(
                report.diagnostics,
                ToolingDetails::Test {
                    contract_revision: None,
                    report: None,
                },
            ));
        }
    };
    let CompiledProject {
        contract,
        registry,
        runtime,
        ..
    } = *project;
    let fixture_yaml = read_utf8(&options.project_root.join("expected-http.yaml"))?;
    let journey = match parse_journey(&fixture_yaml) {
        Ok(journey) => journey,
        Err(_) => {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "fixture.yaml_invalid",
                    "expected-http.yaml",
                    "the fixture journey is not valid strict YAML",
                )],
                ToolingDetails::Test {
                    contract_revision: Some(registry.contract_revision),
                    report: None,
                },
            ));
        }
    };
    let Some(runtime) = runtime else {
        return Ok(ToolingReport::refused(
            vec![diagnostic(
                "fixture.runtime_missing",
                "runtime.yaml",
                "offline fixture execution requires a deployment binding",
            )],
            ToolingDetails::Test {
                contract_revision: Some(registry.contract_revision),
                report: None,
            },
        ));
    };
    let fixture_sql = read_utf8(&options.project_root.join("fixture.sql"))?;
    let temporary = tempfile::tempdir().map_err(|_| ToolingError::Write)?;
    let database = temporary.path().join("fixture.sqlite");
    if materialize_fixture(&database, &fixture_sql).is_err() {
        return Ok(ToolingReport::refused(
            vec![diagnostic(
                "fixture.database_invalid",
                "fixture.sql",
                "the synthetic SQLite fixture could not be materialized",
            )],
            ToolingDetails::Test {
                contract_revision: Some(registry.contract_revision),
                report: None,
            },
        ));
    }
    let bindings = registry
        .sources
        .iter()
        .map(|source| {
            (
                source.id.clone(),
                RuntimeSourceBinding {
                    path: database.clone(),
                },
            )
        })
        .collect();
    let sqlite = match SqliteRuntime::open(
        &registry,
        &bindings,
        SqliteRuntimeLimits {
            request_timeout: Duration::from_millis(runtime.limits.request_timeout_milliseconds),
            concurrent_queries: usize::try_from(runtime.limits.concurrent_queries)
                .unwrap_or(usize::MAX),
        },
    ) {
        Ok(sqlite) => sqlite,
        Err(_) => {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "fixture.source_unavailable",
                    "fixture.sql",
                    "the synthetic SQLite fixture does not satisfy the compiled source contract",
                )],
                ToolingDetails::Test {
                    contract_revision: Some(registry.contract_revision),
                    report: None,
                },
            ));
        }
    };
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ToolingError::Inspect)?;
    let artifacts = generate_artifacts(&registry).map_err(|_| ToolingError::Generate)?;
    let cursor_key = if runtime.cursor.is_some() {
        Some(Arc::new(
            CursorKey::new(vec![0x5a; 32]).map_err(|_| ToolingError::Generate)?,
        ))
    } else {
        None
    };
    let cursor_maximum_age = runtime.cursor.as_ref().map_or(Duration::ZERO, |cursor| {
        Duration::from_secs(cursor.maximum_age_seconds)
    });
    let metadata = ServiceMetadata {
        authority: InstitutionMetadata {
            identifier: contract.registry.authority.identifier.clone(),
            name: contract.registry.authority.name.clone(),
        },
        operator: contract
            .registry
            .operator
            .as_ref()
            .map(|operator| InstitutionMetadata {
                identifier: operator.identifier.clone(),
                name: operator.name.clone(),
            }),
        authoritative_scope: contract.registry.authoritative_scope.clone(),
        alignment_targets: contract
            .registry
            .alignment_targets
            .iter()
            .map(|target| AlignmentMetadata {
                name: target.name.clone(),
                version: target.version.clone(),
                status: target.status.clone(),
                cfr_target: target.cfr_target.clone(),
            })
            .collect(),
    };
    let registry = Arc::new(registry);
    let quota = runtime.quotas.as_ref().map(|quota| QuotaConfig {
        requests_per_minute: quota.requests_per_minute,
        burst: quota.burst,
    });
    let sink = Arc::new(JsonlFileSink::new(temporary.path().join("audit.jsonl")));
    let fixture_report = executor
        .block_on(async {
            let chain = Arc::new(
                ChainState::bootstrap_unkeyed_dev_only(sink.as_ref())
                    .await
                    .map_err(|_| ())?,
            );
            let audit = RelayAudit::new(chain, sink);
            let service = Arc::new(RelayService::new(
                Arc::clone(&registry),
                Arc::new(artifacts),
                Arc::new(sqlite),
                fixture_authenticator(&journey),
                audit,
                cursor_key,
                cursor_maximum_age,
                Duration::from_millis(runtime.limits.request_timeout_milliseconds),
                quota,
                metadata,
            ));
            Ok::<_, ()>(
                execute_fixture_journey(
                    registry.as_ref(),
                    router(service),
                    &journey,
                    options.fixture_id.as_deref(),
                )
                .await,
            )
        })
        .map_err(|_| ToolingError::Inspect)?;
    let details = ToolingDetails::Test {
        contract_revision: Some(registry.contract_revision.clone()),
        report: Some(fixture_report.clone()),
    };
    if fixture_report.is_success() {
        Ok(ToolingReport::success(details))
    } else {
        Ok(ToolingReport::refused(
            fixture_report
                .diagnostics
                .iter()
                .map(|item| diagnostic(&item.code, &item.location, &item.message))
                .collect(),
            details,
        ))
    }
}

pub fn diff_projects(options: &DiffOptions) -> Result<ToolingReport, ToolingError> {
    let previous = compile_project(&options.previous_root, CompileProfile::Authoring)?;
    let current = compile_project(&options.current_root, CompileProfile::Authoring)?;
    let (previous, current) = match (previous, current) {
        (ProjectCompilation::Compiled(previous), ProjectCompilation::Compiled(current)) => {
            (previous.registry, current.registry)
        }
        (previous, current) => {
            let mut diagnostics = Vec::new();
            if let ProjectCompilation::Refused(report) = previous {
                diagnostics.extend(report.diagnostics);
            }
            if let ProjectCompilation::Refused(report) = current {
                diagnostics.extend(report.diagnostics);
            }
            diagnostics.sort_by(|left, right| {
                left.location
                    .cmp(&right.location)
                    .then(left.code.cmp(&right.code))
            });
            return Ok(ToolingReport::refused(
                diagnostics,
                ToolingDetails::Diff { report: None },
            ));
        }
    };
    Ok(ToolingReport::success(ToolingDetails::Diff {
        report: Some(diff_registries(&previous, &current)),
    }))
}

pub fn package_project(options: &PackageOptions) -> Result<ToolingReport, ToolingError> {
    let compilation = compile_project(&options.project_root, CompileProfile::Production)?;
    let project = match compilation {
        ProjectCompilation::Compiled(project) => project,
        ProjectCompilation::Refused(report) => {
            return Ok(ToolingReport::refused(
                report.diagnostics,
                ToolingDetails::Package { manifest: None },
            ));
        }
    };
    let CompiledProject {
        contract, registry, ..
    } = *project;
    let artifacts = generate_artifacts(&registry).map_err(|_| ToolingError::Generate)?;
    let manifest = build_package(
        &options.project_root,
        &options.output_dir,
        &contract,
        &registry,
        &artifacts,
    )
    .map_err(|_| ToolingError::Package)?;
    Ok(ToolingReport::success(ToolingDetails::Package {
        manifest: Some(manifest),
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SchemaStarter<'a> {
    schema_fingerprint: &'a str,
    review_status: &'static str,
    objects: &'a [InspectedObject],
}

enum ProjectCompilation {
    Compiled(Box<CompiledProject>),
    Refused(CompileReport),
}

struct CompiledProject {
    contract: RegistryContract,
    #[allow(dead_code)]
    runtime: Option<RelayRuntime>,
    registry: CompiledRegistry,
    observed: Vec<crate::model::ObservedSourceSchema>,
}

fn compile_project(
    root: &Path,
    profile: CompileProfile,
) -> Result<ProjectCompilation, ToolingError> {
    let contract_yaml = read_utf8(&root.join("registry.yaml"))?;
    let contract = match RegistryContract::parse_yaml(&contract_yaml) {
        Ok(contract) => contract,
        Err(_) => {
            return Ok(ProjectCompilation::Refused(CompileReport {
                diagnostics: vec![diagnostic(
                    "contract.yaml_invalid",
                    "registry.yaml",
                    "the governed contract is not valid strict YAML",
                )],
            }));
        }
    };
    let runtime_path = root.join("runtime.yaml");
    let runtime = if runtime_path.is_file() {
        let yaml = read_utf8(&runtime_path)?;
        match RelayRuntime::parse_yaml(&yaml) {
            Ok(runtime) => Some(runtime),
            Err(_) => {
                return Ok(ProjectCompilation::Refused(CompileReport {
                    diagnostics: vec![diagnostic(
                        "runtime.yaml_invalid",
                        "runtime.yaml",
                        "the deployment binding is not valid strict YAML",
                    )],
                }));
            }
        }
    } else {
        None
    };
    let mut diagnostics = validate_runtime(&contract, runtime.as_ref());
    let observed = match runtime.as_ref() {
        Some(runtime) => {
            observe_sources(root, &contract, runtime).map_err(|_| ToolingError::Inspect)?
        }
        None => Vec::new(),
    };
    if profile == CompileProfile::Production && observed.len() != contract.sources.len() {
        diagnostics.push(diagnostic(
            "runtime.source_unavailable",
            "runtime.yaml.sources",
            "one or more source bindings could not be observed",
        ));
    }
    let governed_files = capture_governed_files(root, &contract)?;
    match compile_contract_with_governed_files(&contract, &observed, profile, &governed_files) {
        Ok(registry) if diagnostics.is_empty() => {
            Ok(ProjectCompilation::Compiled(Box::new(CompiledProject {
                contract,
                runtime,
                registry,
                observed,
            })))
        }
        Ok(_) => Ok(ProjectCompilation::Refused(CompileReport { diagnostics })),
        Err(mut report) => {
            diagnostics.append(&mut report.diagnostics);
            diagnostics.sort_by(|left, right| {
                left.location
                    .cmp(&right.location)
                    .then(left.code.cmp(&right.code))
            });
            Ok(ProjectCompilation::Refused(CompileReport { diagnostics }))
        }
    }
}

fn capture_governed_files(
    root: &Path,
    contract: &RegistryContract,
) -> Result<GovernedFileSet, ToolingError> {
    let mut references = referenced_governed_files(contract)
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let canonical_root = root.canonicalize().map_err(|_| ToolingError::Read)?;
    let review_reference = contract.classifications.provenance_ref.as_str();
    validate_relative(review_reference)?;
    reject_existing_symlink_components(&canonical_root, Path::new(review_reference))?;
    let review_path = canonical_root.join(review_reference);
    if review_path.is_file() {
        let review_bytes = fs::read(&review_path).map_err(|_| ToolingError::Read)?;
        if review_bytes.len() <= 64 * 1024 {
            if let Ok(review) =
                serde_norway::from_slice::<ClassificationReviewDocument>(&review_bytes)
            {
                references.insert(review.rationale_ref);
                if let Some(generated) = review.generated_identification {
                    references.insert(generated.report_ref);
                }
            }
        }
    }
    let mut files = GovernedFileSet::new();
    for reference in references {
        validate_relative(&reference)?;
        reject_existing_symlink_components(&canonical_root, Path::new(&reference))?;
        let candidate = canonical_root.join(&reference);
        let Ok(metadata) = fs::symlink_metadata(&candidate) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ToolingError::UnsafePath);
        }
        let canonical = candidate.canonicalize().map_err(|_| ToolingError::Read)?;
        if !canonical.starts_with(&canonical_root) {
            return Err(ToolingError::UnsafePath);
        }
        files.insert(
            reference,
            fs::read(canonical).map_err(|_| ToolingError::Read)?,
        );
    }
    Ok(files)
}

fn validate_runtime(
    contract: &RegistryContract,
    runtime: Option<&RelayRuntime>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let Some(runtime) = runtime else {
        return diagnostics;
    };
    if runtime.api_version != "relay.registrystack.org/v2alpha1" || runtime.kind != "RelayRuntime" {
        diagnostics.push(diagnostic(
            "runtime.identity_invalid",
            "runtime.yaml",
            "the deployment document identity is unsupported",
        ));
    }
    let governed = contract.sources.keys().collect::<BTreeSet<_>>();
    let bound = runtime.sources.keys().collect::<BTreeSet<_>>();
    if governed != bound {
        diagnostics.push(diagnostic(
            "runtime.source_binding_mismatch",
            "runtime.yaml.sources",
            "runtime sources must bind exactly the governed source identifiers",
        ));
    }
    if contract.resources.iter().any(|resource| {
        resource.operations.list.is_some() || !resource.operations.searches.is_empty()
    }) && runtime.cursor.is_none()
    {
        diagnostics.push(diagnostic(
            "runtime.cursor_missing",
            "runtime.yaml.cursor",
            "a Registry with a list or search operation requires an opaque-cursor key and age bound",
        ));
    }
    let protected = contract.resources.iter().any(|resource| {
        resource
            .operations
            .list
            .iter()
            .flat_map(|operation| {
                operation
                    .access_profiles
                    .iter()
                    .map(|(_, item)| &item.access)
            })
            .chain(resource.operations.read.iter().flat_map(|operation| {
                operation
                    .access_profiles
                    .iter()
                    .map(|(_, item)| &item.access)
            }))
            .chain(resource.operations.lookups.iter().flat_map(|operation| {
                operation
                    .access_profiles
                    .iter()
                    .map(|(_, item)| &item.access)
            }))
            .chain(resource.operations.searches.iter().flat_map(|operation| {
                operation
                    .access_profiles
                    .iter()
                    .map(|(_, item)| &item.access)
            }))
            .any(|access| matches!(access, crate::contract::AccessRule::Protected(_)))
    });
    if protected && runtime.authentication.issuer.is_none() {
        diagnostics.push(diagnostic(
            "runtime.issuer_missing",
            "runtime.yaml.authentication.issuer",
            "a Registry with protected operations requires one configured issuer",
        ));
    }
    diagnostics
}

fn inspected_kind(kind: SchemaObjectKind) -> InspectedObjectKind {
    match kind {
        SchemaObjectKind::Table => InspectedObjectKind::Table,
        SchemaObjectKind::Index => InspectedObjectKind::Index,
        SchemaObjectKind::View => InspectedObjectKind::View,
        SchemaObjectKind::Trigger => InspectedObjectKind::Trigger,
    }
}

fn write_artifacts(output: &Path, artifacts: &ArtifactSet) -> Result<(), ToolingError> {
    if output.exists()
        && fs::symlink_metadata(output)
            .map_err(|_| ToolingError::Read)?
            .file_type()
            .is_symlink()
    {
        return Err(ToolingError::UnsafePath);
    }
    fs::create_dir_all(output).map_err(|_| ToolingError::Write)?;
    for artifact in &artifacts.artifacts {
        validate_relative(&artifact.path)?;
        let path = output.join(&artifact.path);
        reject_existing_symlink_components(output, Path::new(&artifact.path))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| ToolingError::Write)?;
        }
        fs::write(path, &artifact.content).map_err(|_| ToolingError::Write)?;
    }
    Ok(())
}

fn write_generated_relative(
    output: &Path,
    relative: &str,
    content: &[u8],
) -> Result<(), ToolingError> {
    validate_relative(relative)?;
    reject_existing_symlink_components(output, Path::new(relative))?;
    let path = output.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ToolingError::Write)?;
    }
    fs::write(path, content).map_err(|_| ToolingError::Write)
}

fn reject_existing_symlink_components(root: &Path, relative: &Path) -> Result<(), ToolingError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ToolingError::UnsafePath);
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ToolingError::UnsafePath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(ToolingError::Read),
        }
    }
    Ok(())
}

fn write_relative_new(root: &Path, relative: &str, content: &[u8]) -> Result<(), ToolingError> {
    validate_relative(relative)?;
    let path = root.join(relative);
    if path.exists() {
        return Err(ToolingError::Write);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ToolingError::Write)?;
    }
    fs::write(path, content).map_err(|_| ToolingError::Write)
}

fn validate_relative(value: &str) -> Result<(), ToolingError> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ToolingError::UnsafePath);
    }
    Ok(())
}

fn read_utf8(path: &Path) -> Result<String, ToolingError> {
    fs::read_to_string(path).map_err(|_| ToolingError::Read)
}

fn diagnostic(code: &str, location: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.into(),
        location: location.into(),
        message: message.into(),
    }
}

const STARTER_REGISTRY: &str = r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RegistryContract
metadata: {id: registry, version: draft-1, title: Registry authoring workspace}
registry:
  registryIdentifier: urn:example:registry:registry
  name: Registry authoring workspace
  authority: {identifier: urn:example:authority, name: Registry Authority}
  authoritativeScope: Reviewed authoritative records in the declared jurisdiction
  baseUri: https://registry.example.invalid/
  identifierLifecyclePolicyRef: governance/identifier-lifecycle.yaml
  alignmentTargets:
    - {name: govstack-digital-registries, version: 3.0.0-alpha.2, status: directional}
    - {name: govstack-api-design-guide, version: 0.1.0-draft, status: directional}
governance: {controller: urn:example:authority, publisher: urn:example:authority, auditOwner: urn:example:audit-owner}
semantics: {localVocabulary: https://registry.example.invalid/vocabulary/}
classifications:
  privacy: {scheme: https://w3id.org/dpv, version: "2.3"}
  institutional: {scheme: urn:example:classification, version: draft-1}
  handling: {scheme: https://id.registrystack.org/vocab/handling, version: "1"}
  provenanceRef: governance/classification-review.yaml
sources:
  registry: {kind: sqlite, profile: snapshot, expectedSchemaFingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
resources:
  - id: record
    title: Record
    description: Unreviewed starter Record resource
    semanticClass: local:Record
    source: {source: registry, view: registry_records}
    classificationDefaults: {privacy: non-personal, institutional: internal, handling: internal, status: suggested}
    recordContext:
      recordIdentifier: {sourceColumn: record_identifier}
      revisionIdentifier: {sourceColumn: revision_identifier}
      lifecycleState: {sourceColumn: lifecycle_state, codelist: codelists/record-lifecycle.yaml}
      recordedAt: {sourceColumn: recorded_at}
    sourceColumnClassifications: {}
    properties:
      recordValue: {label: Record value, description: Unreviewed starter property, sourceColumn: record_value, type: string, sourceRequired: true, semanticTerm: "local:recordValue"}
    disclosureProfiles: {default: {properties: [recordValue]}}
    operations:
      read:
        defaultAccessProfile: default
        accessProfiles:
          default: {access: {scope: "registry:record:read"}, disclosureProfile: default}
    processingDescriptions:
      - {id: consultation, operationRefs: [read], purpose: reviewed-consultation, recipientClass: authorized-client, legalBasisRef: governance/legal-basis.yaml, dpvProfileRef: governance/processing.dpv.yaml, safeguards: [property-minimization]}
metadataVisibility: {service: public, resources: operation-bound, semantics: operation-bound, classifications: operator-only, processing: operation-bound}
"#;

const STARTER_RUNTIME: &str = r#"apiVersion: relay.registrystack.org/v2alpha1
kind: RelayRuntime
server: {bind: "127.0.0.1:8080"}
packagePath: package
sources: {registry: {path: registry.sqlite}}
authentication: {issuer: null}
audit: {sink: var/audit.jsonl, integrityKeyRef: secret:env/RELAY_AUDIT_KEY}
limits: {requestTimeoutMilliseconds: 1500, concurrentQueries: 8}
"#;

const STARTER_LIFECYCLE: &str =
    "status: suggested\npolicy: Identifiers are stable and are not reassigned after retirement.\n";
const STARTER_CLASSIFICATION: &str = r#"apiVersion: relay.registrystack.org/classification-review/v1
kind: ClassificationReview
registryIdentifier: urn:example:registry:registry
classificationInventoryDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000
method: manual
reviewer: urn:example:authority
reviewDate: pending-review
status: suggested
rationaleRef: governance/legal-basis.yaml
"#;
const STARTER_LEGAL_BASIS: &str = "status: suggested\nlegalBasis: Institutional review is required before production packaging.\n";
const STARTER_PROCESSING: &str = "status: suggested\nprofile: https://w3id.org/dpv/2.3\n";
const STARTER_CODELIST: &str =
    "id: record-lifecycle\nversion: draft-1\nvalues: [ACTIVE, RETIRED]\nstatus: suggested\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn generic_project() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary project root creates");
        let project = temporary.path().join("project");
        let report = init_project(&InitOptions {
            project_root: project.clone(),
        })
        .expect("generic project initializes");
        assert!(report.is_success());
        fs::remove_file(project.join("runtime.yaml"))
            .expect("runtime is optional for an authoring check");
        fs::write(
            project.join("fixture.sql"),
            "-- ROW-VALUE-CANARY REQUEST-VALUE-CANARY PRINCIPAL-VALUE-CANARY\n",
        )
        .expect("generic value canaries write");
        (temporary, project)
    }

    #[test]
    fn errors_never_render_paths() {
        for error in [
            ToolingError::Read,
            ToolingError::Write,
            ToolingError::UnsafePath,
            ToolingError::Inspect,
            ToolingError::Generate,
            ToolingError::Explain,
            ToolingError::Package,
        ] {
            assert!(!error.safe_message().contains('/'));
        }
    }

    #[test]
    fn initialized_contract_is_strictly_parseable() {
        assert!(RegistryContract::parse_yaml(STARTER_REGISTRY).is_ok());
        assert!(RelayRuntime::parse_yaml(STARTER_RUNTIME).is_ok());
    }

    #[test]
    fn check_explanation_is_deterministic_read_only_and_value_free() {
        let (_temporary, project) = generic_project();
        let fixture_path = project.join("fixture.sqlite");
        let generated_path = project.join("generated");
        let fixture_sql = fs::read(project.join("fixture.sql")).expect("fixture canaries read");
        assert!(!fixture_path.exists());
        assert!(!generated_path.exists());

        let options = CheckOptions {
            project_root: project.clone(),
            production: false,
            explain: true,
        };
        let first = check_project(&options).expect("first explanation check completes");
        let second = check_project(&options).expect("second explanation check completes");
        assert!(first.is_success(), "{first:?}");
        assert_eq!(first, second);

        let ToolingDetails::Check {
            operation_explanation: Some(explanation),
            ..
        } = &first.details
        else {
            panic!("successful explanation check returns its canonical explanation");
        };
        let rendered = render_operation_explanation(explanation)
            .expect("operation explanation renders canonically");
        for canary in [
            "ROW-VALUE-CANARY",
            "REQUEST-VALUE-CANARY",
            "PRINCIPAL-VALUE-CANARY",
        ] {
            assert!(
                !rendered
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "operation explanation leaked fixture value"
            );
        }
        assert_eq!(
            fs::read(project.join("fixture.sql")).expect("fixture canaries reread"),
            fixture_sql
        );
        assert!(!fixture_path.exists());
        assert!(!generated_path.exists());
    }

    #[test]
    fn plain_check_omits_the_optional_explanation() {
        let (_temporary, project) = generic_project();
        let report = check_project(&CheckOptions {
            project_root: project,
            production: false,
            explain: false,
        })
        .expect("plain check completes");
        assert!(report.is_success(), "{report:?}");

        let value = serde_json::to_value(report).expect("report serializes");
        assert!(value["details"].get("operation_explanation").is_none());
    }

    #[test]
    fn refused_check_returns_no_partial_explanation() {
        let temporary = tempfile::tempdir().expect("temporary project creates");
        fs::write(temporary.path().join("registry.yaml"), "not: [valid")
            .expect("invalid contract writes");

        let report = check_project(&CheckOptions {
            project_root: temporary.path().to_path_buf(),
            production: false,
            explain: true,
        })
        .expect("invalid project produces a refusal");
        assert!(!report.is_success());
        let ToolingDetails::Check {
            operation_explanation,
            ..
        } = report.details
        else {
            panic!("check returns check details");
        };
        assert!(operation_explanation.is_none());
    }

    #[test]
    fn generate_writes_the_same_canonical_operation_explanation_as_check() {
        let (_project_temporary, project) = generic_project();
        let check = check_project(&CheckOptions {
            project_root: project.clone(),
            production: false,
            explain: true,
        })
        .expect("explanation check completes");
        let ToolingDetails::Check {
            operation_explanation: Some(explanation),
            ..
        } = check.details
        else {
            panic!("check returns an explanation");
        };
        let expected = render_operation_explanation(&explanation)
            .expect("operation explanation renders canonically");

        let temporary = tempfile::tempdir().expect("temporary output creates");
        let report = generate_project(&GenerateOptions {
            project_root: project,
            output_dir: Some(temporary.path().to_path_buf()),
        })
        .expect("generation completes");
        assert!(report.is_success(), "{report:?}");
        assert_eq!(
            fs::read(temporary.path().join(OPERATION_EXPLANATION_PATH))
                .expect("generated explanation reads"),
            expected
        );
        assert!(!temporary
            .path()
            .join("reports/representation-report.json")
            .exists());
    }

    #[test]
    fn fixture_execution_is_isolated_and_reports_no_row_values() {
        let project_name = ["business", "registry"].join("-");
        let project = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/relay-v2/acceptance")
            .join(project_name);
        let runtime_path = project.join("runtime.yaml");
        let source_path = project.join("fixture.sql");
        let runtime_before = fs::read(&runtime_path).expect("runtime reads");
        let source_before = fs::read(&source_path).expect("fixture source reads");
        assert!(!project.join("fixture.sqlite").exists());

        let report = test_project(&TestOptions {
            project_root: project.clone(),
            fixture_id: Some("identifier-read".into()),
        })
        .expect("fixture operation completes");
        assert!(report.is_success(), "{report:?}");

        assert_eq!(
            fs::read(runtime_path).expect("runtime rereads"),
            runtime_before
        );
        assert_eq!(
            fs::read(source_path).expect("fixture source rereads"),
            source_before
        );
        assert!(!project.join("fixture.sqlite").exists());
        let rendered = serde_json::to_string(&report).expect("report serializes");
        for protected in [
            "Example Orchard Cooperative",
            "BIZ-SYNTH-0001",
            "registration_number",
        ] {
            assert!(!rendered.contains(protected), "report leaked fixture data");
        }
    }
}
