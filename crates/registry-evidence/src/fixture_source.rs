//! Offline acquisition runs reviewed pack code against sealed recorded exchanges.
//!
//! These programs carry no deployment binding, secret resolver or live network
//! capability. Each case compiles the captured pack closure before replay.
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, OnceLock,
    },
};

use chrono::{DateTime, Utc};
use registry_adapter_core::{Intercept, RecordedExchange};
use registry_adapter_engine::{
    evidence::{
        compile_evidence_pack_with_protocols, EvidenceAcquisitionIntent, EvidenceExecutionError,
        EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits, EvidenceSendIntent,
    },
    replay::ReplayTranscript,
    route::EvidenceHttpDiagnostic,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::TempDir;

use crate::{
    bundle::{Bundle, RuntimeBindingPlanError, SourcePack},
    config::SourceConfig,
    kernel::KernelError,
    model::LookupResult,
    pack_source::authorized_route_inputs,
    selector::ResolvedAuthorization,
};

/// One offline run's explicitly supplied SQLite snapshots. The directory is
/// retained for the complete run, so a captured file cannot disappear while
/// an Adapter program still holds its identity and digest binding.
pub struct FixtureAssets {
    _directory: TempDir,
    captured_sqlite: BTreeMap<String, registry_platform_sqlite::CapturedSnapshot>,
}

impl FixtureAssets {
    /// Materialize bounded, reviewed fixture SQL beneath caller-owned scratch
    /// space and capture each resulting immutable SQLite snapshot.
    pub fn materialize_in(
        scratch_root: &Path,
        extracts: &BTreeMap<String, String>,
    ) -> Result<Self, KernelError> {
        if extracts.len() > crate::bundle::MAX_BUNDLE_FILES {
            return Err(KernelError::Bundle);
        }
        let mut total_bytes = 0_u64;
        for (profile, sql) in extracts {
            registry_platform_yaml::LocalId::new(profile).map_err(|_| KernelError::Bundle)?;
            let bytes = u64::try_from(sql.len()).map_err(|_| KernelError::Bundle)?;
            if sql.is_empty() || bytes > crate::bundle::MAX_ARTIFACT_BYTES {
                return Err(KernelError::Bundle);
            }
            total_bytes = total_bytes.checked_add(bytes).ok_or(KernelError::Bundle)?;
            if total_bytes > crate::bundle::MAX_BUNDLE_BYTES {
                return Err(KernelError::Bundle);
            }
        }
        let directory = tempfile::Builder::new()
            .prefix("registry-evidence-fixture-")
            .tempdir_in(scratch_root)
            .map_err(|_| KernelError::Bundle)?;
        let mut captured_sqlite = BTreeMap::new();
        for (index, (profile, sql)) in extracts.iter().enumerate() {
            let path = directory.path().join(format!("extract-{index}.sqlite"));
            registry_platform_sqlite::materialize_fixture(&path, sql)
                .map_err(|_| KernelError::Bundle)?;
            let captured = registry_platform_sqlite::CapturedSnapshot::capture(&path)
                .map_err(|_| KernelError::Bundle)?;
            captured_sqlite.insert(profile.clone(), captured);
        }
        Ok(Self {
            _directory: directory,
            captured_sqlite,
        })
    }

    fn captured_sqlite(&self) -> &BTreeMap<String, registry_platform_sqlite::CapturedSnapshot> {
        &self.captured_sqlite
    }
}

/// An exact ordered transcript. Every source send must match and consume one
/// exchange, and unconsumed entries fail the case rather than imply coverage.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureAcquisition {
    pub intercepts: Vec<Intercept>,
    pub exchanges: Vec<RecordedExchange>,
}

pub struct OfflineSourceProgram {
    source: SourceConfig,
    closure: SourcePack,
}

/// One offline acquisition outcome and the physical data operations it
/// attempted. OAuth token requests are not Evidence data operations.
pub struct FixtureRun {
    pub outcome: Result<LookupResult, KernelError>,
    /// The governed input names projected after authorization and schema
    /// validation. Values never leave the execution boundary.
    pub prepared_inputs: Option<Vec<String>>,
    /// Whether the engine reached the acquisition-intent hook.
    pub acquisition_started: bool,
    /// Data-operation attempts admitted before credential resolution. OAuth
    /// token requests are not Evidence data operations.
    pub data_operations: u64,
    /// The endpoint and closed HTTP cause the engine retained when the route
    /// failed on a response status, as the runtime reports it to operators.
    pub http_cause: Option<(String, EvidenceHttpDiagnostic)>,
}

#[derive(Default)]
struct FixtureIntent {
    prepared_inputs: OnceLock<Vec<String>>,
    acquisition_started: AtomicBool,
    data_operations: AtomicU64,
    http_cause: OnceLock<(String, EvidenceHttpDiagnostic)>,
}

impl EvidenceHostHooks for FixtureIntent {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async {
            self.acquisition_started.store(true, Ordering::Release);
            Ok(())
        })
    }

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async {
            self.data_operations.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }
}

impl OfflineSourceProgram {
    fn checked_pack(
        &self,
    ) -> Result<registry_adapter_engine::evidence::EvidencePackProgram, KernelError> {
        let pack = self.closure.pack();
        let artifacts = self.closure.artifacts();
        compile_evidence_pack_with_protocols(
            &pack,
            self.source.route.as_str(),
            &artifacts,
            EvidenceLimits::default(),
            &crate::host_protocol::registry().map_err(|_| KernelError::Bundle)?,
        )
        .map_err(|_| KernelError::Bundle)
    }

    /// Materialize the current fixture grammar's one reviewed extract without
    /// exposing Adapter engine binding details to the command host.
    pub fn materialize_single_extract_in(
        &self,
        scratch_root: &Path,
        seed_sql: &str,
    ) -> Result<FixtureAssets, KernelError> {
        let mut profiles = self.checked_pack()?.required_extract_profiles().into_iter();
        let profile = profiles.next().ok_or(KernelError::Bundle)?;
        if profiles.next().is_some() {
            return Err(KernelError::Bundle);
        }
        FixtureAssets::materialize_in(
            scratch_root,
            &BTreeMap::from([(profile, seed_sql.to_owned())]),
        )
    }

    pub async fn execute(
        &self,
        resolved: &ResolvedAuthorization,
        fixture: FixtureAcquisition,
        observed_at: DateTime<Utc>,
    ) -> Result<LookupResult, KernelError> {
        self.execute_observed(resolved, fixture, None, observed_at)
            .await
            .outcome
    }

    /// Execute one case and retain the actual physical data-operation count,
    /// including an operation whose route later fails.
    pub async fn execute_observed(
        &self,
        resolved: &ResolvedAuthorization,
        fixture: FixtureAcquisition,
        assets: Option<&FixtureAssets>,
        observed_at: DateTime<Utc>,
    ) -> FixtureRun {
        let hooks = Arc::new(FixtureIntent::default());
        let outcome = self
            .execute_inner(resolved, fixture, assets, observed_at, Arc::clone(&hooks))
            .await;
        FixtureRun {
            outcome,
            prepared_inputs: hooks.prepared_inputs.get().cloned(),
            acquisition_started: hooks.acquisition_started.load(Ordering::Acquire),
            data_operations: hooks.data_operations.load(Ordering::Relaxed),
            http_cause: hooks.http_cause.get().cloned(),
        }
    }

    async fn execute_inner(
        &self,
        resolved: &ResolvedAuthorization,
        fixture: FixtureAcquisition,
        assets: Option<&FixtureAssets>,
        observed_at: DateTime<Utc>,
        hooks: Arc<FixtureIntent>,
    ) -> Result<LookupResult, KernelError> {
        let inputs = authorized_route_inputs(&self.source, resolved)
            .map_err(|_| KernelError::Preparation)?;
        let checked = self.checked_pack()?;
        if !checked.input_schema().validate(&inputs) {
            return Err(KernelError::Preparation);
        }
        let transcript = Arc::new(ReplayTranscript::from_exchanges(
            fixture.intercepts,
            fixture.exchanges,
        ));
        let program = if let Some(assets) = assets {
            checked.bind_fixture(Arc::clone(&transcript), assets.captured_sqlite().clone())
        } else {
            checked.bind_replay(Arc::clone(&transcript))
        }
        .map_err(|_| KernelError::Bundle)?;
        let mut prepared_inputs = inputs
            .as_object()
            .ok_or(KernelError::Preparation)?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        prepared_inputs.sort_unstable();
        hooks
            .prepared_inputs
            .set(prepared_inputs)
            .map_err(|_| KernelError::Bundle)?;
        let acquisition = if program.requires_access_attribution() {
            let context = registry_adapter_engine::host_protocol::HostAccessAttribution::try_new(
                "offline-fixture-principal",
                &resolved.purpose,
            )
            .map_err(|_| KernelError::Preparation)?;
            program
                .begin_acquisition_at_with_attribution(
                    hooks.clone(),
                    Arc::new(context),
                    observed_at,
                )
                .await
        } else {
            program
                .begin_acquisition_at(hooks.clone(), observed_at)
                .await
        }
        .map_err(|_| KernelError::SourceProtocol)?;
        let outcome = program
            .execute(&acquisition, inputs)
            .await
            .map_err(|error| {
                if let EvidenceExecutionError::Route(route) = &error {
                    if let Some((endpoint, cause)) = route
                        .evidence_diagnostic
                        .as_ref()
                        .and_then(|diagnostic| diagnostic.http_parts())
                    {
                        // One execution fails once, so the cell is empty here.
                        let _ = hooks.http_cause.set((endpoint.to_owned(), cause));
                    }
                }
                KernelError::SourceProtocol
            });
        transcript
            .finish()
            .map_err(|_| KernelError::SourceProtocol)?;
        crate::pack_source::lookup_result(outcome?).map_err(|_| KernelError::SourceProtocol)
    }

    /// Execute against sealed HTTP exchanges and explicit captured SQLite
    /// fixture assets. No live binding, credential, TLS authority, or network
    /// capability is introduced.
    pub async fn execute_with_assets(
        &self,
        resolved: &ResolvedAuthorization,
        fixture: FixtureAcquisition,
        assets: &FixtureAssets,
        observed_at: DateTime<Utc>,
    ) -> Result<LookupResult, KernelError> {
        self.execute_observed(resolved, fixture, Some(assets), observed_at)
            .await
            .outcome
    }
}

/// Pure compilation is identical for package checks and fixture execution.
/// Runtime secrets and captured deployment extracts are never consulted here.
pub fn compile_sources(
    bundle: &Bundle,
) -> Result<BTreeMap<String, OfflineSourceProgram>, KernelError> {
    bundle
        .config
        .sources
        .iter()
        .map(|(id, source)| {
            let closure = bundle.source_pack(id).ok_or(KernelError::Bundle)?;
            let pack = closure.pack();
            let artifacts = closure.artifacts();
            compile_evidence_pack_with_protocols(
                &pack,
                source.route.as_str(),
                &artifacts,
                EvidenceLimits::default(),
                &crate::host_protocol::registry().map_err(|_| KernelError::Bundle)?,
            )
            .map_err(|error| {
                RuntimeBindingPlanError::SourcePlan {
                    artifact_prefix: source.pack.artifact_prefix.as_str().to_owned(),
                    error,
                }
                .artifact_fault()
                .map(KernelError::Artifact)
                .unwrap_or(KernelError::Bundle)
            })?;
            Ok((
                id.to_owned(),
                OfflineSourceProgram {
                    source: source.clone(),
                    closure: closure.clone(),
                },
            ))
        })
        .collect()
}

/// Parse the closed transcript without interpreting a raw provider response as
/// an already resolved fact set.
pub fn fixture_acquisition(value: &Value) -> Result<FixtureAcquisition, KernelError> {
    serde_json::from_value(value.clone()).map_err(|_| KernelError::SourceProtocol)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};

    use chrono::{DateTime, Utc};
    use registry_adapter_engine::component::sqlite_extract::SqliteExtractSource;
    use registry_platform_sqlite::{
        ColumnContract, ColumnType, StatementContract, StatementLimits,
    };
    use serde_json::json;

    use super::{compile_sources, FixtureAcquisition, FixtureAssets};

    fn scratch_root() -> PathBuf {
        let root = PathBuf::from(
            std::env::var_os("CARGO_TARGET_DIR").expect("fixture tests require a volume target"),
        )
        .join("registry-evidence-fixture-assets");
        std::fs::create_dir_all(&root).expect("fixture scratch root");
        root
    }

    #[tokio::test]
    async fn fixture_assets_materialize_actual_reviewed_sql_and_own_its_lifetime() {
        let assets = FixtureAssets::materialize_in(
            &scratch_root(),
            &BTreeMap::from([(
                "people".to_owned(),
                "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
                 INSERT INTO evidence_extract VALUES('2026-10-31T12:00:00Z', 'fixture', 'extract-a'); \
                 CREATE TABLE people(id TEXT, private_canary TEXT); \
                 INSERT INTO people VALUES('0007', 'DO-NOT-DISCLOSE');"
                    .to_owned(),
            )]),
        )
        .expect("fixture assets");
        let source = SqliteExtractSource::open(
            assets
                .captured_sqlite()
                .get("people")
                .expect("named captured extract")
                .clone(),
            StatementContract {
                sql: "SELECT id FROM people WHERE id = :id".to_owned(),
                columns: vec![ColumnContract {
                    name: "id".to_owned(),
                    value_type: ColumnType::String,
                }],
                parameters: vec![registry_platform_sqlite::ParameterContract {
                    name: "id".to_owned(),
                    required: true,
                }],
                limits: StatementLimits {
                    maximum_rows: 1,
                    maximum_cell_bytes: 64,
                    maximum_response_bytes: 512,
                    maximum_statement_steps: 10_000,
                    timeout: Duration::from_secs(1),
                    concurrency: 1,
                },
                schema: None,
            },
            Duration::from_secs(3600),
        )
        .expect("reviewed statement opens");
        assert_eq!(
            source
                .execute(
                    &BTreeMap::from([(
                        "id".to_owned(),
                        registry_platform_sqlite::Value::String("0007".to_owned()),
                    )]),
                    DateTime::parse_from_rfc3339("2026-10-31T12:30:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                )
                .await
                .expect("actual fixture query")["rows"],
            json!([{"id": "0007"}])
        );
    }

    #[tokio::test]
    async fn reviewed_sqlite_reference_executes_and_refuses_a_missing_profile() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle",
        );
        let verified = registry_platform_config::verify_package(
            &root,
            &crate::bundle::evidence_package_limits(),
            "evidencectl package",
        )
        .expect("reference package verifies");
        let bundle =
            crate::bundle::Bundle::load_as_found(&root, &verified).expect("reference bundle loads");
        let requirement = bundle.config.requirements.first().expect("one requirement");
        let fixture_path = requirement
            .fixtures
            .as_ref()
            .expect("fixture path")
            .as_str();
        let fixture = serde_json::to_value(&bundle.fixtures[fixture_path]).expect("fixture value");
        let case = fixture["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|case| case["id"] == "positive")
            .and_then(serde_json::Value::as_object)
            .expect("positive case");
        let resolved = crate::selector::resolve_offline_fixture_authorization(
            &bundle,
            requirement,
            fixture["common"].as_object(),
            case,
            "urn:registry-evidence:offline-evaluation",
        )
        .expect("fixture authorization");
        let programs = compile_sources(&bundle).expect("source pack compiles");
        let program = &programs[requirement.initial_source()];
        let assets = program
            .materialize_single_extract_in(
                &scratch_root(),
                fixture["common"]["extract"]
                    .as_str()
                    .expect("reviewed fixture SQL"),
            )
            .expect("single extract materializes");
        let observed_at = DateTime::parse_from_rfc3339(
            fixture["common"]["observedAt"]
                .as_str()
                .expect("fixed observation time"),
        )
        .unwrap()
        .with_timezone(&Utc);
        let run = program
            .execute_observed(
                &resolved,
                FixtureAcquisition {
                    intercepts: Vec::new(),
                    exchanges: Vec::new(),
                },
                Some(&assets),
                observed_at,
            )
            .await;
        assert_eq!(
            run.prepared_inputs,
            Some(vec!["recordReference".to_owned()])
        );
        assert!(run.acquisition_started);
        assert_eq!(run.data_operations, 1);
        let acquired = run.outcome.expect("actual reviewed SQLite route");
        assert!(matches!(
            acquired,
            crate::model::LookupResult::Match(ref facts)
                if facts.len() == 1
                    && facts.get("active_licence_count") == Some(&json!(1))
        ));

        let missing = FixtureAssets::materialize_in(&scratch_root(), &BTreeMap::new())
            .expect("an explicit empty fixture has no hidden source");
        let missing_run = program
            .execute_observed(
                &resolved,
                FixtureAcquisition {
                    intercepts: Vec::new(),
                    exchanges: Vec::new(),
                },
                Some(&missing),
                observed_at,
            )
            .await;
        assert_eq!(missing_run.prepared_inputs, None);
        assert!(!missing_run.acquisition_started);
        assert_eq!(missing_run.data_operations, 0);
        assert!(matches!(
            missing_run.outcome,
            Err(crate::kernel::KernelError::Bundle)
        ));

        let mut incomplete = resolved.clone();
        incomplete.subjects[0].fields.clear();
        let unprepared = program
            .execute_observed(
                &incomplete,
                FixtureAcquisition {
                    intercepts: Vec::new(),
                    exchanges: Vec::new(),
                },
                Some(&assets),
                observed_at,
            )
            .await;
        assert_eq!(unprepared.prepared_inputs, None);
        assert!(!unprepared.acquisition_started);
        assert_eq!(unprepared.data_operations, 0);
        assert!(matches!(
            unprepared.outcome,
            Err(crate::kernel::KernelError::Preparation)
        ));
    }
}
