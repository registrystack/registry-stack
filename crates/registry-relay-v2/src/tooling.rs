// SPDX-License-Identifier: Apache-2.0
//! Shared authoring facade used verbatim by `relayctl`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::{ChainState, JsonlFileSink};
use registry_platform_sqlite::{
    inspect_schema as inspect_sqlite_schema, materialize_fixture, CapturedSnapshot,
    DatabaseProfile, LiveDatabaseFile, SchemaObjectKind,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifacts::{generate_artifacts, ArtifactSet};
use crate::audit::RelayAudit;
use crate::authoring::validate_runtime;
use crate::compiler::{
    classification_inventory_digest, compile_contract_with_governed_files,
    referenced_governed_files, GovernedFileSet,
};
use crate::contract::{
    AccessRule, ClassificationPartial, ClassificationReviewDocument, Handling, ProtectedAccess,
    RegistryContract, RelayRuntime, ResourceSource, ReviewStatus, SdmxBindingDefinition,
    StatisticalAttributeDefinition, StatisticalBindings, StatisticalDimensionDefinition,
    StatisticalMeasureDefinition, StatisticalPublication, StatisticalQueryProfile,
    StatisticalValueType, MAXIMUM_RUNTIME_BYTES,
};
use crate::cursor::CursorKey;
use crate::diff::{diff_registries, ChangeImpactReport};
use crate::fixtures::{
    execute_fixture_journey, fixture_authenticator, parse_journey, FixturePlanReport,
};
use crate::identification::{
    access_profile_report, classification_inventory_report, classification_review_starter,
    contextual_review_findings, identify_contract, render_access_profile_report,
    render_classification_inventory_report, render_classification_review_yaml,
    render_contextual_review_findings, render_identification_report, ACCESS_PROFILE_REPORT_PATH,
    CLASSIFICATION_INVENTORY_REPORT_PATH, CLASSIFICATION_REVIEW_STARTER_PATH,
    CONTEXTUAL_REVIEW_FINDINGS_PATH, IDENTIFICATION_REPORT_PATH,
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
    pub profile: InspectionProfile,
    pub statistical_view: Option<String>,
    pub time_column: Option<String>,
    pub measure_column: Option<String>,
    pub attribute_columns: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionProfile {
    Snapshot,
    #[default]
    LiveReadOnly,
}

#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub project_root: PathBuf,
    pub production: bool,
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        statistical_starter_file: Option<String>,
    },
    Check {
        contract_revision: Option<String>,
        production: bool,
        configuration_key_paths: Option<ConfigurationKeyPaths>,
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
    let profile = match options.profile {
        InspectionProfile::Snapshot => DatabaseProfile::Snapshot(
            CapturedSnapshot::capture(&options.database_path).map_err(|_| ToolingError::Inspect)?,
        ),
        InspectionProfile::LiveReadOnly => DatabaseProfile::LiveReadOnly(
            LiveDatabaseFile::bind(&options.database_path).map_err(|_| ToolingError::Inspect)?,
        ),
    };
    let catalog =
        inspect_sqlite_schema(&profile, &inspection_limits()).map_err(|_| ToolingError::Inspect)?;
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
    let statistical_selection = match (
        options.statistical_view.as_deref(),
        options.time_column.as_deref(),
        options.measure_column.as_deref(),
    ) {
        (None, None, None) if options.attribute_columns.is_empty() => None,
        (Some(view), Some(time), Some(measure)) => Some((view, time, measure)),
        _ => {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "statistics.starter_selection_incomplete",
                    "--statistical-view",
                    "a statistical starter requires one view, one explicit time column, and one explicit measure column",
                )],
                ToolingDetails::SchemaInspection {
                    fingerprint: catalog.fingerprint,
                    objects,
                    starter_file: None,
                    statistical_starter_file: None,
                },
            ));
        }
    };
    if statistical_selection.is_some() && options.starter_output.is_none() {
        return Ok(ToolingReport::refused(
            vec![diagnostic(
                "statistics.starter_output_missing",
                "--starters",
                "a statistical starter requires an explicit starter output directory",
            )],
            ToolingDetails::SchemaInspection {
                fingerprint: catalog.fingerprint,
                objects,
                starter_file: None,
                statistical_starter_file: None,
            },
        ));
    }
    let statistical_starter = if let Some((view_name, time_column, measure_column)) =
        statistical_selection
    {
        let Some(view) = objects
            .iter()
            .find(|object| object.kind == InspectedObjectKind::View && object.name == view_name)
        else {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "statistics.starter_view_unknown",
                    "--statistical-view",
                    "the selected statistical starter view is absent from the inspected schema",
                )],
                ToolingDetails::SchemaInspection {
                    fingerprint: catalog.fingerprint,
                    objects,
                    starter_file: None,
                    statistical_starter_file: None,
                },
            ));
        };
        let selected_time = view
            .columns
            .iter()
            .find(|column| column.name == time_column);
        let selected_measure = view
            .columns
            .iter()
            .find(|column| column.name == measure_column);
        if time_column == measure_column || selected_time.is_none() || selected_measure.is_none() {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "statistics.starter_column_invalid",
                    "--time-column",
                    "the time and measure columns must be distinct exact columns in the selected statistical view",
                )],
                ToolingDetails::SchemaInspection {
                    fingerprint: catalog.fingerprint,
                    objects,
                    starter_file: None,
                    statistical_starter_file: None,
                },
            ));
        }
        let selected_attributes = options.attribute_columns.iter().collect::<BTreeSet<_>>();
        if selected_attributes.len() != options.attribute_columns.len()
            || selected_attributes
                .iter()
                .any(|column| column.as_str() == time_column || column.as_str() == measure_column)
            || selected_attributes.iter().any(|column| {
                !view
                    .columns
                    .iter()
                    .any(|candidate| candidate.name == column.as_str())
            })
        {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "statistics.starter_attribute_invalid",
                    "--attribute-column",
                    "attribute columns must be distinct exact non-time, non-measure columns in the selected statistical view",
                )],
                ToolingDetails::SchemaInspection {
                    fingerprint: catalog.fingerprint,
                    objects,
                    starter_file: None,
                    statistical_starter_file: None,
                },
            ));
        }
        if !selected_time
            .is_some_and(|column| compatible_suggested_time_type(&column.declared_type))
            || !selected_measure
                .is_some_and(|column| compatible_suggested_measure_type(&column.declared_type))
        {
            return Ok(ToolingReport::refused(
                vec![diagnostic(
                    "statistics.starter_column_type_invalid",
                    "--time-column/--measure-column",
                    "select a text-like time column and a numeric measure column from the statistical view",
                )],
                ToolingDetails::SchemaInspection {
                    fingerprint: catalog.fingerprint,
                    objects,
                    starter_file: None,
                    statistical_starter_file: None,
                },
            ));
        }
        Some(statistical_starter(
            view,
            time_column,
            measure_column,
            &options.attribute_columns,
        ))
    } else {
        None
    };
    let mut statistical_starter_file = None;
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
        if let Some(statistical_starter) = statistical_starter {
            let content =
                serde_norway::to_string(&statistical_starter).map_err(|_| ToolingError::Write)?;
            fs::write(output.join("statistical-dataset-starter.yaml"), content)
                .map_err(|_| ToolingError::Write)?;
            statistical_starter_file = Some("statistical-dataset-starter.yaml".into());
        }
        Some("schema-starter.yaml".into())
    } else {
        None
    };
    Ok(ToolingReport::success(ToolingDetails::SchemaInspection {
        fingerprint: catalog.fingerprint,
        objects,
        starter_file,
        statistical_starter_file,
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
            }))
        }
        ProjectCompilation::Refused(report) => Ok(ToolingReport::refused(
            report.diagnostics,
            ToolingDetails::Check {
                contract_revision: None,
                production: options.production,
                configuration_key_paths: None,
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
                        | "resources[].operations.list.accessProfiles"
                        | "resources[].operations.read.accessProfiles"
                        | "resources[].operations.lookups[].accessProfiles"
                        | "resources[].operations.searches[].accessProfiles"
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
    let access_profiles = access_profile_report(&registry, &classification_digest)
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
            "access-profile-report",
            ACCESS_PROFILE_REPORT_PATH,
            render_access_profile_report(&access_profiles).map_err(|_| ToolingError::Generate)?,
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
    if let Some(diagnostic) = generation_destination_diagnostic(&output)? {
        return Ok(ToolingReport::refused(
            vec![diagnostic],
            ToolingDetails::Generate {
                contract_revision: Some(registry.contract_revision),
                artifacts: Vec::new(),
            },
        ));
    }
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
    let project_root = options
        .project_root
        .canonicalize()
        .map_err(|_| ToolingError::Read)?;
    let project_parent = project_root.parent().ok_or(ToolingError::Write)?;
    validate_fixture_workspace_parent(project_parent)?;
    let temporary = fixture_workspace(project_parent)?;
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

#[cfg(unix)]
fn validate_fixture_workspace_parent(parent: &Path) -> Result<(), ToolingError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective_user = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| ToolingError::Write)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !trusted_fixture_workspace_parent_mode(
                metadata.uid(),
                metadata.permissions().mode(),
                effective_user,
            )
        {
            return Err(ToolingError::Write);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_fixture_workspace_parent(_parent: &Path) -> Result<(), ToolingError> {
    Err(ToolingError::Write)
}

#[cfg(unix)]
fn trusted_fixture_workspace_parent_mode(owner: u32, mode: u32, effective_user: u32) -> bool {
    let trusted_owner = owner == 0 || owner == effective_user;
    let not_writable_by_others = mode & 0o022 == 0;
    let protected_shared_parent = owner == 0 && mode & 0o1000 != 0;
    trusted_owner && (not_writable_by_others || protected_shared_parent)
}

fn fixture_workspace(project_parent: &Path) -> Result<tempfile::TempDir, ToolingError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".relayctl-test-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder
        .tempdir_in(project_parent)
        .map_err(|_| ToolingError::Write)
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatisticalDatasetStarterPatch {
    statistical_datasets: Vec<StatisticalDatasetStarter>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatisticalDatasetStarter {
    id: String,
    title: String,
    description: String,
    publication: StatisticalPublication,
    source: ResourceSource,
    classification_defaults: ClassificationPartial,
    dimensions: BTreeMap<String, StatisticalDimensionDefinition>,
    time: StatisticalTimeDimensionStarter,
    measure: StatisticalMeasureDefinition,
    attributes: BTreeMap<String, StatisticalAttributeDefinition>,
    access: AccessRule,
    query: StatisticalQueryProfile,
    bindings: StatisticalBindings,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatisticalTimeDimensionStarter {
    label: String,
    description: String,
    column: String,
    granularity: &'static str,
    concept: String,
    classification: ClassificationPartial,
}

fn statistical_starter(
    view: &InspectedObject,
    time_column: &str,
    measure_column: &str,
    attribute_columns: &[String],
) -> StatisticalDatasetStarterPatch {
    let classification = suggested_statistical_classification();
    let mut dimensions = Vec::new();
    let mut attributes = Vec::new();
    for column in &view.columns {
        if column.name == time_column || column.name == measure_column {
            continue;
        }
        let id = to_authoring_id(&column.name);
        if attribute_columns.contains(&column.name) {
            attributes.push((
                id.clone(),
                StatisticalAttributeDefinition {
                    label: id.clone(),
                    description: "Review this explicitly selected observation attribute.".into(),
                    column: column.name.clone(),
                    data_type: suggested_dimension_type(&column.declared_type),
                    vocabulary: None,
                    required: !column.nullable,
                    concept: format!("local:{id}"),
                    classification: classification.clone(),
                },
            ));
        } else {
            dimensions.push((
                id.clone(),
                StatisticalDimensionDefinition {
                    label: id.clone(),
                    description: "Review this schema-derived suggested dimension.".into(),
                    column: column.name.clone(),
                    data_type: suggested_dimension_type(&column.declared_type),
                    vocabulary: None,
                    concept: format!("local:{id}"),
                    classification: classification.clone(),
                },
            ));
        }
    }
    let time_id = to_authoring_id(time_column);
    let measure_id = to_authoring_id(measure_column);
    let measure_type = view
        .columns
        .iter()
        .find(|column| column.name == measure_column)
        .map_or(StatisticalValueType::Decimal, |column| {
            suggested_measure_type(&column.declared_type)
        });
    let id = to_kebab_id(&view.name);
    StatisticalDatasetStarterPatch {
        statistical_datasets: vec![StatisticalDatasetStarter {
            id: id.clone(),
            title: id,
            description: "Review this schema-derived statistical dataset before publication."
                .into(),
            publication: StatisticalPublication {
                release_at: "REVIEW_REQUIRED".into(),
            },
            source: ResourceSource {
                source: "REVIEW_REQUIRED".into(),
                view: view.name.clone(),
            },
            classification_defaults: classification.clone(),
            dimensions: dimensions.into_iter().collect(),
            time: StatisticalTimeDimensionStarter {
                label: time_id.clone(),
                description: "Review this explicitly selected time-period dimension.".into(),
                column: time_column.into(),
                granularity: "REVIEW_REQUIRED",
                concept: format!("local:{time_id}"),
                classification: classification.clone(),
            },
            measure: StatisticalMeasureDefinition {
                id: measure_id.clone(),
                label: measure_id.clone(),
                description: "Review this explicitly selected measure.".into(),
                column: measure_column.into(),
                data_type: measure_type,
                concept: format!("local:{measure_id}"),
                classification,
            },
            attributes: attributes.into_iter().collect(),
            access: AccessRule::Protected(ProtectedAccess {
                scope: "statistics:review-required:read".into(),
                purpose: None,
                authority_row_binding: None,
            }),
            query: StatisticalQueryProfile {
                allow_unfiltered: false,
                maximum_observations: 1_000,
                maximum_offset: 0,
            },
            bindings: StatisticalBindings {
                sdmx: SdmxBindingDefinition::default(),
            },
        }],
    }
}

fn suggested_statistical_classification() -> ClassificationPartial {
    ClassificationPartial {
        privacy: Some("review-required".into()),
        institutional: Some("review-required".into()),
        handling: Some(Handling::Restricted),
        status: Some(ReviewStatus::Suggested),
    }
}

fn suggested_dimension_type(declared_type: &str) -> StatisticalValueType {
    let declared = declared_type.to_ascii_uppercase();
    if declared.contains("INT") {
        StatisticalValueType::Integer
    } else if declared.contains("REAL")
        || declared.contains("FLOA")
        || declared.contains("DOUB")
        || declared.contains("DEC")
        || declared.contains("NUM")
    {
        StatisticalValueType::Decimal
    } else if declared == "BOOLEAN" {
        StatisticalValueType::Boolean
    } else {
        StatisticalValueType::String
    }
}

fn suggested_measure_type(declared_type: &str) -> StatisticalValueType {
    if declared_type.to_ascii_uppercase().contains("INT") {
        StatisticalValueType::Integer
    } else {
        StatisticalValueType::Decimal
    }
}

fn compatible_suggested_time_type(declared_type: &str) -> bool {
    let declared = declared_type.trim().to_ascii_uppercase();
    declared.contains("CHAR")
        || declared.contains("CLOB")
        || declared.contains("TEXT")
        || declared == "DATE"
        || declared == "DATETIME"
}

fn compatible_suggested_measure_type(declared_type: &str) -> bool {
    let declared = declared_type.trim().to_ascii_uppercase();
    declared.contains("INT")
        || declared.contains("REAL")
        || declared.contains("FLOA")
        || declared.contains("DOUB")
        || declared.contains("DEC")
        || declared.contains("NUM")
}

fn to_authoring_id(value: &str) -> String {
    let mut output = String::new();
    let mut uppercase_next = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            let character = character.to_ascii_lowercase();
            if output.is_empty() {
                if character.is_ascii_digit() {
                    output.push_str("component");
                }
                output.push(character);
            } else if uppercase_next {
                output.push(character.to_ascii_uppercase());
                uppercase_next = false;
            } else {
                output.push(character);
            }
        } else if !output.is_empty() {
            uppercase_next = true;
        }
    }
    if output.is_empty() {
        "component".into()
    } else {
        output
    }
}

fn to_kebab_id(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
        } else if !output.is_empty() && !output.ends_with('-') {
            output.push('-');
        }
    }
    output.trim_matches('-').to_owned()
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
        let yaml = read_runtime_utf8(&runtime_path)?;
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
        write_new_file(&path, &artifact.content)?;
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
    write_new_file(&path, content)
}

fn generation_destination_diagnostic(output: &Path) -> Result<Option<Diagnostic>, ToolingError> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ToolingError::Read),
    };
    if metadata.file_type().is_symlink() {
        return Err(ToolingError::UnsafePath);
    }
    if !metadata.is_dir() {
        return Ok(Some(diagnostic(
            "generation.destination_not_empty",
            ".",
            "generation requires a new or empty output directory",
        )));
    }
    let mut entries = fs::read_dir(output).map_err(|_| ToolingError::Read)?;
    Ok(entries.next().map(|_| {
        diagnostic(
            "generation.destination_not_empty",
            ".",
            "generation requires a new or empty output directory",
        )
    }))
}

fn write_new_file(path: &Path, content: &[u8]) -> Result<(), ToolingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ToolingError::Write)?;
    file.write_all(content).map_err(|_| ToolingError::Write)
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

fn read_runtime_utf8(path: &Path) -> Result<String, ToolingError> {
    let mut file = fs::File::open(path).map_err(|_| ToolingError::Read)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAXIMUM_RUNTIME_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ToolingError::Read)?;
    if bytes.len() as u64 > MAXIMUM_RUNTIME_BYTES {
        return Err(ToolingError::Read);
    }
    String::from_utf8(bytes).map_err(|_| ToolingError::Read)
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
    datasetIdentifier: records
    entityTypeIdentifier: record
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
    use crate::compiler::tests as compiler_tests;

    fn runtime(authentication: &str) -> RelayRuntime {
        let mut runtime =
            RelayRuntime::parse_yaml(STARTER_RUNTIME).expect("starter runtime parses");
        runtime.authentication =
            serde_norway::from_str(authentication).expect("authentication parses");
        runtime
    }

    #[test]
    fn errors_never_render_paths() {
        for error in [
            ToolingError::Read,
            ToolingError::Write,
            ToolingError::UnsafePath,
            ToolingError::Inspect,
            ToolingError::Generate,
            ToolingError::Package,
        ] {
            assert!(!error.safe_message().contains('/'));
        }
    }

    #[cfg(unix)]
    #[test]
    fn fixture_workspace_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = tempfile::tempdir().expect("workspace parent");
        let project = parent.path().join("project");
        fs::create_dir(&project).expect("project directory");
        let workspace = fixture_workspace(parent.path()).expect("fixture workspace");

        assert!(!workspace.path().starts_with(&project));
        assert_eq!(workspace.path().parent(), Some(parent.path()));
        assert_eq!(
            fs::metadata(workspace.path())
                .expect("workspace metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn fixture_workspace_parent_requires_trusted_ownership_and_mode() {
        let effective_user = 1000;
        assert!(trusted_fixture_workspace_parent_mode(
            effective_user,
            0o040755,
            effective_user
        ));
        assert!(trusted_fixture_workspace_parent_mode(
            0,
            0o041777,
            effective_user
        ));
        assert!(!trusted_fixture_workspace_parent_mode(
            effective_user + 1,
            0o040755,
            effective_user
        ));
        assert!(!trusted_fixture_workspace_parent_mode(
            effective_user,
            0o040775,
            effective_user
        ));
        assert!(!trusted_fixture_workspace_parent_mode(
            effective_user + 1,
            0o041777,
            effective_user
        ));
    }

    #[test]
    fn initialized_contract_is_strictly_parseable() {
        assert!(RegistryContract::parse_yaml(STARTER_REGISTRY).is_ok());
        assert!(RelayRuntime::parse_yaml(STARTER_RUNTIME).is_ok());
    }

    #[test]
    fn tooling_runtime_loading_matches_the_startup_issuer_profile() {
        let runtime = |discovery_url: &str| {
            STARTER_RUNTIME.replace(
                "authentication: {issuer: null}",
                &format!(
                    "authentication:\n  issuer:\n    id: issuer\n    discoveryUrl: {discovery_url}\n    audience: registry\n    tokenTypes: [at+jwt]\n    algorithms: [EdDSA]"
                ),
            )
        };
        let valid = "https://identity.example.invalid/.well-known/openid-configuration";
        assert!(RelayRuntime::parse_yaml(&runtime(valid)).is_ok());

        let temporary = tempfile::tempdir().expect("temporary root");
        fs::write(
            temporary.path().join("registry.yaml"),
            compiler_tests::valid_contract(),
        )
        .expect("contract writes");
        for invalid in [
            "https://operator:credential@identity.example.invalid/.well-known/openid-configuration",
            "https://identity.example.invalid/.well-known/openid-configuration?tenant=x",
            "https://identity.example.invalid/.well-known/openid-configuration#fragment",
            "https://identity.example.invalid/.well-known/oauth-authorization-server",
            "https:///.well-known/openid-configuration",
        ] {
            fs::write(temporary.path().join("runtime.yaml"), runtime(invalid))
                .expect("runtime writes");
            let ProjectCompilation::Refused(report) =
                compile_project(temporary.path(), CompileProfile::Authoring)
                    .expect("invalid runtime is a tooling refusal")
            else {
                panic!("invalid issuer profile compiled: {invalid}");
            };
            assert!(report
                .diagnostics
                .iter()
                .any(|item| item.code == "runtime.yaml_invalid"));
        }
    }

    #[test]
    fn tooling_runtime_reads_match_the_startup_byte_ceiling() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let path = temporary.path().join("runtime.yaml");
        fs::write(&path, vec![b' '; MAXIMUM_RUNTIME_BYTES as usize])
            .expect("boundary runtime writes");
        assert_eq!(
            read_runtime_utf8(&path)
                .expect("the exact startup byte ceiling reads")
                .len(),
            MAXIMUM_RUNTIME_BYTES as usize
        );

        fs::write(&path, vec![b' '; MAXIMUM_RUNTIME_BYTES as usize + 1])
            .expect("oversized runtime writes");
        assert!(matches!(read_runtime_utf8(&path), Err(ToolingError::Read)));
        fs::write(
            temporary.path().join("registry.yaml"),
            compiler_tests::valid_contract(),
        )
        .expect("contract writes");
        assert!(matches!(
            compile_project(temporary.path(), CompileProfile::Authoring),
            Err(ToolingError::Read)
        ));
    }

    #[test]
    fn tooling_requires_an_issuer_for_protected_statistical_access() {
        let mut contract = RegistryContract::parse_yaml(compiler_tests::statistical_contract())
            .expect("statistical contract");
        contract.statistical_datasets[0].access =
            serde_norway::from_str("{scope: registry:statistics:read}")
                .expect("protected statistical access");

        let diagnostics = validate_runtime(&contract, Some(&runtime("{issuer: null}")));
        assert!(diagnostics
            .iter()
            .any(|item| item.code == "runtime.issuer_missing"));
    }

    #[test]
    fn ordinary_writable_publisher_database_can_be_inspected_live_without_values() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let database = temporary.path().join("publisher.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE registry_records (identifier TEXT PRIMARY KEY, label TEXT NOT NULL);\nINSERT INTO registry_records VALUES ('private-id', 'private-value');",
        )
        .expect("publisher database materializes");

        let report = inspect_schema(&InspectOptions {
            database_path: database,
            starter_output: None,
            profile: InspectionProfile::LiveReadOnly,
            statistical_view: None,
            time_column: None,
            measure_column: None,
            attribute_columns: Vec::new(),
        })
        .expect("live structure inspection succeeds");
        assert!(report.is_success());
        let rendered = serde_json::to_string(&report).expect("inspection serializes");
        assert!(!rendered.contains("private-id"));
        assert!(!rendered.contains("private-value"));
        assert!(rendered.contains("registry_records"));
        assert!(rendered.contains("identifier"));
    }

    #[test]
    fn schema_only_inspection_writes_one_review_gated_statistical_starter() {
        let temporary = tempfile::tempdir().expect("temporary directory creates");
        let database = temporary.path().join("statistics.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE observations (ref_area TEXT NOT NULL, time_period TEXT NOT NULL, obs_value REAL NOT NULL, unit_measure TEXT NOT NULL);\nCREATE VIEW published_rates AS SELECT ref_area, time_period, obs_value, unit_measure FROM observations;\nINSERT INTO observations VALUES ('ROW-VALUE-CANARY', 'VALUE-CANARY', 99.5, 'PRIVATE-CANARY');",
        )
        .expect("fixture materializes");
        let output = temporary.path().join("starters");

        let report = inspect_schema(&InspectOptions {
            database_path: database,
            starter_output: Some(output.clone()),
            profile: InspectionProfile::Snapshot,
            statistical_view: Some("published_rates".into()),
            time_column: Some("time_period".into()),
            measure_column: Some("obs_value".into()),
            attribute_columns: vec!["unit_measure".into()],
        })
        .expect("schema inspection completes");

        assert!(report.is_success(), "{report:?}");
        let rendered_report = serde_json::to_value(&report).expect("inspection report serializes");
        assert_eq!(
            rendered_report.pointer("/details/statistical_starter_file"),
            Some(&serde_json::Value::String(
                "statistical-dataset-starter.yaml".into()
            ))
        );
        let rendered_report = rendered_report.to_string();
        for row_value in ["ROW-VALUE-CANARY", "VALUE-CANARY", "99.5", "PRIVATE-CANARY"] {
            assert!(
                !rendered_report.contains(row_value),
                "inspection report exposed a source row value"
            );
        }
        let ToolingDetails::SchemaInspection {
            statistical_starter_file,
            ..
        } = report.details
        else {
            panic!("schema inspection details are returned");
        };
        assert_eq!(
            statistical_starter_file.as_deref(),
            Some("statistical-dataset-starter.yaml")
        );
        let starter = fs::read_to_string(output.join("statistical-dataset-starter.yaml"))
            .expect("starter reads");
        let patch: serde_norway::Value =
            serde_norway::from_str(&starter).expect("starter is valid YAML");
        let datasets = patch
            .get("statisticalDatasets")
            .and_then(serde_norway::Value::as_sequence)
            .expect("starter contains statistical datasets");
        assert_eq!(datasets.len(), 1);
        assert!(starter.contains("status: suggested"));
        assert!(starter.contains("releaseAt: REVIEW_REQUIRED"));
        assert!(starter.contains("granularity: REVIEW_REQUIRED"));
        assert!(starter.contains("view: published_rates"));
        assert!(starter.contains("column: time_period"));
        assert!(starter.contains("column: obs_value"));
        assert!(starter.contains("column: unit_measure"));
        assert!(starter.contains("sdmx: {}"));
        for row_value in ["ROW-VALUE-CANARY", "VALUE-CANARY", "99.5", "PRIVATE-CANARY"] {
            assert!(
                !starter.contains(row_value),
                "starter read a source row value"
            );
        }
    }

    #[test]
    fn statistical_inspection_refuses_unreviewable_component_selections() {
        let temporary = tempfile::tempdir().expect("temporary directory creates");
        let database = temporary.path().join("statistics.sqlite");
        materialize_fixture(
            &database,
            "CREATE TABLE observations (period_number INTEGER NOT NULL, value_label TEXT NOT NULL);\nCREATE VIEW published_rates AS SELECT period_number, value_label FROM observations;",
        )
        .expect("fixture materializes");

        let incomplete = inspect_schema(&InspectOptions {
            database_path: database.clone(),
            starter_output: Some(temporary.path().join("incomplete")),
            profile: InspectionProfile::Snapshot,
            statistical_view: Some("published_rates".into()),
            time_column: Some("period_number".into()),
            measure_column: None,
            attribute_columns: Vec::new(),
        })
        .expect("schema inspection completes");
        assert!(!incomplete.is_success());
        assert_eq!(
            incomplete.diagnostics[0].code,
            "statistics.starter_selection_incomplete"
        );

        let invalid_attribute = inspect_schema(&InspectOptions {
            database_path: database.clone(),
            starter_output: Some(temporary.path().join("invalid-attribute")),
            profile: InspectionProfile::Snapshot,
            statistical_view: Some("published_rates".into()),
            time_column: Some("period_number".into()),
            measure_column: Some("value_label".into()),
            attribute_columns: vec!["period_number".into()],
        })
        .expect("schema inspection completes");
        assert!(!invalid_attribute.is_success());
        assert_eq!(
            invalid_attribute.diagnostics[0].code,
            "statistics.starter_attribute_invalid"
        );

        let incompatible = inspect_schema(&InspectOptions {
            database_path: database,
            starter_output: Some(temporary.path().join("incompatible")),
            profile: InspectionProfile::Snapshot,
            statistical_view: Some("published_rates".into()),
            time_column: Some("period_number".into()),
            measure_column: Some("value_label".into()),
            attribute_columns: Vec::new(),
        })
        .expect("schema inspection completes");
        assert!(!incompatible.is_success());
        assert_eq!(
            incompatible.diagnostics[0].code,
            "statistics.starter_column_type_invalid"
        );
        assert!(!temporary
            .path()
            .join("incompatible/statistical-dataset-starter.yaml")
            .exists());
    }

    #[test]
    fn statistical_starter_identifiers_are_camel_case_for_common_sql_names() {
        assert_eq!(to_authoring_id("REF_AREA"), "refArea");
        assert_eq!(to_authoring_id("time_period"), "timePeriod");
        assert_eq!(to_authoring_id("2024_VALUE"), "component2024Value");
    }

    #[test]
    fn generation_refuses_a_nonempty_destination_without_changing_user_files() {
        let temporary = tempfile::tempdir().expect("temporary root");
        let output = temporary.path().join("generated");
        fs::create_dir(&output).expect("output directory");
        let marker = output.join("operator-notes.txt");
        fs::write(&marker, b"keep me").expect("marker writes");

        let refusal = generation_destination_diagnostic(&output)
            .expect("destination is inspected")
            .expect("nonempty destination is refused");
        assert_eq!(refusal.code, "generation.destination_not_empty");
        assert_eq!(fs::read(marker).expect("marker remains"), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn generation_refuses_a_symlink_destination() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary root");
        let destination = temporary.path().join("destination");
        fs::create_dir(&destination).expect("destination directory");
        let output = temporary.path().join("generated");
        symlink(&destination, &output).expect("output symlink");

        assert!(matches!(
            generation_destination_diagnostic(&output),
            Err(ToolingError::UnsafePath)
        ));
    }

    #[test]
    fn production_runtime_validation_matches_lookup_and_metadata_requirements() {
        let mut lookup_contract =
            RegistryContract::parse_yaml(compiler_tests::valid_contract()).expect("contract");
        lookup_contract.resources[0].operations.lookups.push(
            serde_norway::from_str(
                "id: by-name\nrequestBody:\n  maximumBytes: 128\n  selectors:\n    name: {sourceColumn: name, type: string, minimumBytes: 1, maximumBytes: 32}\ndefaultAccessProfile: public\naccessProfiles:\n  public: {access: public, disclosureProfile: public}\n",
            )
            .expect("lookup parses"),
        );
        let lookup_diagnostics =
            validate_runtime(&lookup_contract, Some(&runtime("{issuer: null}")));
        assert!(lookup_diagnostics
            .iter()
            .any(|item| item.code == "runtime.lookup_quota_missing"));

        let mut metadata_contract =
            RegistryContract::parse_yaml(compiler_tests::valid_contract()).expect("contract");
        let template = metadata_contract.resources[0].clone();
        let mut second = template;
        second.id = "second-record".into();
        metadata_contract.resources.push(second);
        let metadata_diagnostics =
            validate_runtime(&metadata_contract, Some(&runtime("{issuer: null}")));
        assert!(metadata_diagnostics
            .iter()
            .any(|item| item.code == "runtime.cursor_missing"));

        metadata_contract.metadata_visibility.resources = crate::contract::Visibility::OperatorOnly;
        let operator_only_diagnostics =
            validate_runtime(&metadata_contract, Some(&runtime("{issuer: null}")));
        assert!(!operator_only_diagnostics
            .iter()
            .any(|item| item.code == "runtime.cursor_missing"));

        metadata_contract.metadata_visibility.resources = crate::contract::Visibility::Public;
        metadata_contract.resources[1].operations.read = Some(
            serde_norway::from_str(
                "defaultAccessProfile: protected\naccessProfiles:\n  protected: {access: {scope: 'registry:record:read'}, disclosureProfile: public}\n",
            )
            .expect("protected read operation"),
        );
        let one_public_diagnostics =
            validate_runtime(&metadata_contract, Some(&runtime("{issuer: null}")));
        assert!(!one_public_diagnostics
            .iter()
            .any(|item| item.code == "runtime.cursor_missing"));

        metadata_contract.metadata_visibility.resources =
            crate::contract::Visibility::OperationBound;
        let operation_bound_diagnostics =
            validate_runtime(&metadata_contract, Some(&runtime("{issuer: null}")));
        assert!(operation_bound_diagnostics
            .iter()
            .any(|item| item.code == "runtime.cursor_missing"));
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
