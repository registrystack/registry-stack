//! Retained contract tests for reviewed SQLite statements through Evidence's
//! current Adapter pack boundary.
//!
//! The pack owns the reviewed SQL, parameter origins, projection and extraction
//! script. Evidence still owns authorized input minimization, acquisition time,
//! credential isolation and closed value-free failures.
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use registry_adapter_core::{AdapterEndpointBindings, AdapterPack};
use registry_adapter_engine::artifacts::PackArtifactBytes;
use registry_adapter_engine::component::sqlite_extract::{SqliteExtractError, SqliteExtractPlan};
use registry_adapter_engine::evidence::{
    EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits,
    EvidenceRuntimeBindings, EvidenceSendIntent,
};
use registry_evidence::bundle::{evidence_package_limits, Bundle};
use registry_evidence::config::{AuthorityKind, ValueOrigin};
use registry_evidence::fixture_source::{compile_sources, FixtureAcquisition};
use registry_evidence::kernel::KernelError;
use registry_evidence::model::LookupResult;
use registry_evidence::pack_source::{PackSourceError, PackSourceExecutor, PackSourceFailure};
use registry_evidence::selector::{
    ResolvedAuthorization, ResolvedSelectorField, ResolvedSelectorValue, ResolvedSubject,
    ResolvedSubjectScope,
};
use registry_platform_config::{sha256_uri, SecretResolver};
use registry_platform_sqlite::{materialize_fixture, CapturedSnapshot, ErrorKind};
use serde_json::{json, Map, Value as JsonValue};
use tempfile::TempDir;

/// The bundle artifact every plan below names for its statement.
const STATEMENT_ARTIFACT: &str = "queries/residence-region.sql";
const EXTRACT_PROFILE: &str = "residence-register";
const SUBJECT_PROFILE: &str = "record-reference-v1";
const PUBLISHED_AT: &str = "2026-08-07T02:00:00Z";
const EVALUATED_AT: &str = "2026-08-07T03:00:00Z";

/// A value that must never reach a rendered diagnostic, placed both in the
/// statement text and in the extract data.
const CANARY: &str = "s3cr3t-canary-value";

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("the test instant is RFC 3339")
        .with_timezone(&Utc)
}

fn scratch_root() -> PathBuf {
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("registry-evidence-statement-source");
    fs::create_dir_all(&root).expect("the statement-source scratch root is available");
    root
}

fn scratch_directory(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(scratch_root())
        .expect("a statement-source scratch directory")
}

#[derive(Clone, Copy)]
enum InputKind {
    String,
    Integer,
}

impl InputKind {
    fn schema(self) -> JsonValue {
        match self {
            Self::String => json!({"type":"string"}),
            Self::Integer => json!({"type":"integer"}),
        }
    }

    fn selector_config(self) -> JsonValue {
        match self {
            Self::String => json!({"type":"string", "minimumBytes":1, "maximumBytes":128}),
            Self::Integer => json!({"type":"integer", "minimum":-1_000_000, "maximum":1_000_000}),
        }
    }
}

#[derive(Clone)]
struct Input {
    name: String,
    selector_field: String,
    kind: InputKind,
}

/// One reviewed pack plan, varied only where a retained outcome needs it.
struct Plan {
    statement: String,
    columns: Vec<(String, &'static str)>,
    parameters: Vec<String>,
    inputs: Vec<Input>,
    query_parameters: Map<String, JsonValue>,
    prefix_steps: Vec<JsonValue>,
    script_prefix: String,
    maximum_rows: u64,
    maximum_cell_bytes: u64,
    maximum_extract_age_seconds: u64,
}

impl Default for Plan {
    fn default() -> Self {
        Self {
            statement: "SELECT id FROM person ORDER BY id".to_owned(),
            columns: vec![("id".to_owned(), "string")],
            parameters: Vec::new(),
            inputs: Vec::new(),
            query_parameters: Map::new(),
            prefix_steps: Vec::new(),
            script_prefix: String::new(),
            maximum_rows: 8,
            maximum_cell_bytes: 4096,
            maximum_extract_age_seconds: 86_400,
        }
    }
}

impl Plan {
    fn statement(mut self, statement: &str) -> Self {
        self.statement = statement.to_owned();
        self
    }

    fn columns(mut self, columns: &[(&str, &'static str)]) -> Self {
        self.columns = columns
            .iter()
            .map(|(name, kind)| ((*name).to_owned(), *kind))
            .collect();
        self
    }

    fn input(mut self, name: &str, selector_field: &str, kind: InputKind) -> Self {
        self.inputs.push(Input {
            name: name.to_owned(),
            selector_field: selector_field.to_owned(),
            kind,
        });
        self
    }

    fn parameter(mut self, name: &str, expression: JsonValue) -> Self {
        self.parameters.push(name.to_owned());
        self.query_parameters.insert(name.to_owned(), expression);
        self
    }

    fn declared_parameter(mut self, name: &str) -> Self {
        self.parameters.push(name.to_owned());
        self
    }

    fn route_parameter(mut self, name: &str, expression: JsonValue) -> Self {
        self.query_parameters.insert(name.to_owned(), expression);
        self
    }

    fn derived_parameter(mut self, name: &str, script: &str, entrypoint: &str) -> Self {
        self.parameters.push(name.to_owned());
        self.script_prefix.push_str(script);
        self.script_prefix.push('\n');
        self.prefix_steps.push(json!({"setProperty": {
            "name": name,
            "value": {"rhai": {"file":"scripts/source.rhai", "entrypoint":entrypoint}}
        }}));
        self.query_parameters
            .insert(name.to_owned(), json!({"exchangeProperty":name}));
        self
    }

    fn rows(mut self, maximum_rows: u64) -> Self {
        self.maximum_rows = maximum_rows;
        self
    }

    fn cell_bytes(mut self, maximum_cell_bytes: u64) -> Self {
        self.maximum_cell_bytes = maximum_cell_bytes;
        self
    }

    fn extract_age(mut self, maximum_extract_age_seconds: u64) -> Self {
        self.maximum_extract_age_seconds = maximum_extract_age_seconds;
        self
    }

    fn pack_documents(&self) -> (AdapterPack, PackArtifactBytes, Vec<u8>, Vec<u8>) {
        let inputs_properties = self
            .inputs
            .iter()
            .map(|input| (input.name.clone(), input.kind.schema()))
            .collect::<Map<_, _>>();
        let inputs_required = self
            .inputs
            .iter()
            .map(|input| JsonValue::String(input.name.clone()))
            .collect::<Vec<_>>();
        let row_properties = self
            .columns
            .iter()
            .map(|(name, kind)| {
                let schema = match *kind {
                    "string" => json!({"type":"string", "maxLength":65_536}),
                    "integer" => json!({
                        "type":"integer", "minimum":i64::MIN, "maximum":i64::MAX
                    }),
                    "boolean" => json!({"type":"boolean"}),
                    other => panic!("unsupported synthetic column type {other}"),
                };
                (name.clone(), schema)
            })
            .collect::<Map<_, _>>();
        let row_required = self
            .columns
            .iter()
            .map(|(name, _)| JsonValue::String(name.clone()))
            .collect::<Vec<_>>();
        let inputs = serde_json::to_vec(&json!({
            "type":"object", "additionalProperties":false,
            "properties":inputs_properties, "required":inputs_required
        }))
        .expect("the inputs schema serializes");
        let facts = serde_json::to_vec(&json!({
            "type":"object", "additionalProperties":false,
            "properties":{"result":{"type":"array", "maxItems":8, "items":{
                "type":"object", "additionalProperties":false,
                "properties":row_properties, "required":row_required
            }}},
            "required":["result"]
        }))
        .expect("the facts schema serializes");
        let script = format!(
            "{}\nfn facts(exchange) {{\n  #{{lookup: \"matched\", facts: #{{result: exchange.body.rows}}}}\n}}\n",
            self.script_prefix
        )
        .into_bytes();
        let mut steps = self.prefix_steps.clone();
        steps.push(
            json!({"to": {"uri":"sqlite-extract:statement", "parameters":{
                "queryParameters":self.query_parameters
            }}}),
        );
        steps.push(json!({"setBody":{"rhai":{
            "file":"scripts/source.rhai", "entrypoint":"facts"
        }}}));
        let columns = self
            .columns
            .iter()
            .map(|(name, kind)| json!({"name":name, "type":kind}))
            .collect::<Vec<_>>();
        let parameters = self
            .parameters
            .iter()
            .map(|name| json!({"name":name, "required":true}))
            .collect::<Vec<_>>();
        let pack: AdapterPack = serde_json::from_value(json!({
            "id":"statement-source", "version":"1", "testedVersions":[],
            "endpoints":[{
                "id":"statement", "component":"sqlite-extract",
                "authentication":{"type":"none"},
                "attemptTimeoutMilliseconds":10_000,
                "maximumResponseBytes":65_536,
                "sqliteExtract":{
                    "extractProfile":EXTRACT_PROFILE,
                    "statement":{"path":STATEMENT_ARTIFACT, "digest":sha256_uri(self.statement.as_bytes())},
                    "columns":columns, "parameters":parameters,
                    "maximumExtractAgeSeconds":self.maximum_extract_age_seconds,
                    "maximumRows":self.maximum_rows,
                    "maximumCellBytes":self.maximum_cell_bytes,
                    "maximumStatementSteps":100_000,
                    "concurrency":2
                }
            }],
            "scripts":[{"path":"scripts/source.rhai", "digest":sha256_uri(&script)}],
            "sourceRoutes":[{
                "id":"lookup",
                "evidence":{
                    "inputsSchema":{"path":"schemas/inputs.json", "digest":sha256_uri(&inputs)},
                    "factsSchema":{"path":"schemas/facts.json", "digest":sha256_uri(&facts)},
                    "acquisitionPosture":"field-projected"
                },
                "steps":steps
            }]
        }))
        .expect("the reviewed Adapter pack parses");
        let artifacts = PackArtifactBytes::new([
            (
                STATEMENT_ARTIFACT.to_owned(),
                self.statement.as_bytes().to_vec(),
            ),
            ("scripts/source.rhai".to_owned(), script),
            ("schemas/inputs.json".to_owned(), inputs.clone()),
            ("schemas/facts.json".to_owned(), facts.clone()),
        ]);
        (pack, artifacts, inputs, facts)
    }
}

fn reference_bundle_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/sqlite-extract-evidence/bundle",
    )
}

fn copy_bundle_files(source: &Path, destination: &Path, relative: &Path) {
    for entry in fs::read_dir(source.join(relative)).expect("the reference bundle is readable") {
        let entry = entry.expect("the reference bundle entry is readable");
        let child = relative.join(entry.file_name());
        let child_text = child.to_string_lossy();
        if child_text == "SHA256SUMS" || child_text.starts_with("adapter-packs/") {
            continue;
        }
        let kind = entry.file_type().expect("the reference entry has a type");
        if kind.is_dir() {
            copy_bundle_files(source, destination, &child);
        } else if kind.is_file() {
            let target = destination.join(&child);
            fs::create_dir_all(target.parent().expect("a copied file has a parent"))
                .expect("the copied bundle directory is created");
            fs::copy(entry.path(), target).expect("the reference bundle file is copied");
        } else {
            panic!("the maintained reference bundle contains an unsupported entry");
        }
    }
}

struct PreparedPack {
    _directory: TempDir,
    bundle: Bundle,
}

fn prepared_pack(plan: &Plan) -> PreparedPack {
    let directory = scratch_directory("pack-");
    copy_bundle_files(
        reference_bundle_root().as_path(),
        directory.path(),
        Path::new(""),
    );

    let (pack, _artifacts, inputs, facts) = plan.pack_documents();
    let mut pack_document = serde_json::to_value(&pack).expect("the pack serializes");
    let pack_object = pack_document
        .as_object_mut()
        .expect("an Adapter pack is an object");
    pack_object.insert(
        "apiVersion".to_owned(),
        json!("id.registrystack.org/formats/adapter/pack/v1alpha1"),
    );
    pack_object.insert("kind".to_owned(), json!("AdapterPack"));
    let pack_bytes = serde_json::to_vec_pretty(&pack_document).expect("the pack serializes");
    let pack_digest = sha256_uri(&pack_bytes);
    let pack_prefix = format!(
        "adapter-packs/statement-source/{}",
        pack_digest
            .strip_prefix("sha256:")
            .expect("a SHA-256 URI has its prefix")
    );

    let config_path = directory.path().join("evidence.yaml");
    let mut config: JsonValue = serde_norway::from_slice(
        &fs::read(&config_path).expect("the maintained Evidence config is readable"),
    )
    .expect("the maintained Evidence config parses");
    config["selectorProfiles"][SUBJECT_PROFILE]["maximumAggregateBytes"] = json!(512);
    let selector_fields = config["selectorProfiles"][SUBJECT_PROFILE]["fields"]
        .as_object_mut()
        .expect("the selector profile has fields");
    for input in &plan.inputs {
        selector_fields.insert(input.selector_field.clone(), input.kind.selector_config());
    }
    let source = &mut config["sources"]["licence-register"];
    source["pack"] = json!({
        "id":"statement-source", "version":"1", "digest":pack_digest,
        "artifactPrefix":pack_prefix
    });
    source["route"] = json!("lookup");
    source["posture"] = json!("field-projected");
    source["inputs"] = JsonValue::Object(
        plan.inputs
            .iter()
            .map(|input| {
                (
                    input.name.clone(),
                    json!({"selector":{
                        "role":"subject", "profile":SUBJECT_PROFILE,
                        "field":input.selector_field
                    }}),
                )
            })
            .collect(),
    );
    fs::write(
        &config_path,
        serde_norway::to_string(&config).expect("the Evidence config serializes"),
    )
    .expect("the Evidence config is written");

    let pack_root = directory.path().join(&pack_prefix);
    for (relative, bytes) in [
        ("pack.yaml", pack_bytes.as_slice()),
        (STATEMENT_ARTIFACT, plan.statement.as_bytes()),
        ("schemas/inputs.json", inputs.as_slice()),
        ("schemas/facts.json", facts.as_slice()),
    ] {
        let path = pack_root.join(relative);
        fs::create_dir_all(path.parent().expect("a pack artifact has a parent"))
            .expect("the pack artifact directory is created");
        fs::write(path, bytes).expect("the pack artifact is written");
    }
    let script = format!(
        "{}\nfn facts(exchange) {{\n  #{{lookup: \"matched\", facts: #{{result: exchange.body.rows}}}}\n}}\n",
        plan.script_prefix
    );
    let script_path = pack_root.join("scripts/source.rhai");
    fs::create_dir_all(script_path.parent().expect("the script has a parent"))
        .expect("the script directory is created");
    fs::write(script_path, script).expect("the pack script is written");
    fs::write(
        directory
            .path()
            .join("schemas/professional-licence-facts.schema.yaml"),
        &facts,
    )
    .expect("the projected facts schema is written");

    let verified = registry_platform_config::write_sum_file(
        directory.path(),
        None,
        &evidence_package_limits(),
        "rebuild the synthetic statement-source package",
    )
    .expect("the synthetic package is sealed");
    let bundle = Bundle::load_as_found(directory.path(), &verified)
        .expect("the synthetic statement-source package loads");
    PreparedPack {
        _directory: directory,
        bundle,
    }
}

fn extract_seed(published_at: &str) -> String {
    format!(
        "CREATE TABLE evidence_extract(published_at TEXT, publisher TEXT, extract_id TEXT); \
         INSERT INTO evidence_extract VALUES('{published_at}', 'urn:example:publisher', '2026-08-07-full'); \
         CREATE TABLE person(id TEXT PRIMARY KEY, region_code TEXT, rank INTEGER, note TEXT); \
         INSERT INTO person VALUES \
           ('p-1', 'nw', 1, 'short'), \
           ('p-2', 'nw', 2, '{CANARY} and a note long enough to overrun a small cell bound'), \
           ('p-3', 'se', 1, 'other');"
    )
}

fn captured_extract(seed: &str) -> (TempDir, CapturedSnapshot, PathBuf) {
    let directory = scratch_directory("extract-");
    let path = directory.path().join("extract.sqlite");
    materialize_fixture(&path, seed).expect("the extract fixture materializes");
    let captured = CapturedSnapshot::capture(&path).expect("the immutable extract is captured");
    (directory, captured, path)
}

#[derive(Default)]
struct AllowAcquisition;

impl EvidenceHostHooks for AllowAcquisition {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn before_credentials<'a>(&'a self, _intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct LiveCase {
    executor: PackSourceExecutor,
    pack: Arc<AdapterPack>,
    artifacts: Arc<PackArtifactBytes>,
    _package: PreparedPack,
    _extract: TempDir,
    extract_path: PathBuf,
}

fn compile_live(plan: &Plan, seed: &str) -> Result<LiveCase, PackSourceError> {
    let package = prepared_pack(plan);
    let source = package
        .bundle
        .config
        .sources
        .get("licence-register")
        .expect("the synthetic source");
    let closure = package
        .bundle
        .source_pack("licence-register")
        .expect("the synthetic pack closure");
    let pack = closure.pack();
    let artifacts = closure.artifacts();
    let (extract, captured, extract_path) = captured_extract(seed);
    let bindings: AdapterEndpointBindings = serde_json::from_value(json!({
        "id":source.connection(), "endpoints":[], "allowedPrivateCidrs":[]
    }))
    .expect("the credential-free runtime binding parses");
    let runtime = EvidenceRuntimeBindings::with_captured_sqlite(
        bindings,
        SecretResolver::disabled(),
        BTreeMap::from([(EXTRACT_PROFILE.to_owned(), captured)]),
    );
    let executor =
        PackSourceExecutor::compile(source, closure, &runtime, &[], EvidenceLimits::default())?;
    Ok(LiveCase {
        executor,
        pack,
        artifacts,
        _package: package,
        _extract: extract,
        extract_path,
    })
}

async fn run(
    executor: &PackSourceExecutor,
    inputs: JsonValue,
    at: &str,
) -> Result<LookupResult, PackSourceError> {
    executor
        .execute(inputs, instant(at), Arc::new(AllowAcquisition))
        .await
}

async fn run_diagnosed(
    executor: &PackSourceExecutor,
    inputs: JsonValue,
    at: &str,
) -> Result<LookupResult, PackSourceFailure> {
    executor
        .execute_diagnosed(inputs, instant(at), Arc::new(AllowAcquisition))
        .await
}

fn matched_rows(rows: JsonValue) -> LookupResult {
    LookupResult::Match(BTreeMap::from([("result".to_owned(), rows)]))
}

fn authorization(fields: &[(&str, ResolvedSelectorValue)]) -> ResolvedAuthorization {
    ResolvedAuthorization {
        authority_profile: "licence-verifier-v1".to_owned(),
        authority_kind: AuthorityKind::Statutory,
        grant_id: None,
        requirement: "urn:gov:example:requirement:licence-register-status:v1".to_owned(),
        purpose: "professional-licence-verification".to_owned(),
        subject_scope: ResolvedSubjectScope::Audience("urn:example:consumer".to_owned()),
        subjects: vec![ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: SUBJECT_PROFILE.to_owned(),
            value_origin: ValueOrigin::Request,
            fields: fields
                .iter()
                .map(|(name, value)| ResolvedSelectorField {
                    name: (*name).to_owned(),
                    value: value.clone(),
                })
                .collect(),
        }],
    }
}

#[tokio::test]
async fn a_statement_source_executes_and_returns_projected_json() {
    let plan = Plan::default()
        .statement("SELECT id FROM person WHERE region_code = :region ORDER BY id")
        .input("region", "region_code", InputKind::String)
        .parameter("region", json!({"jsonpath":"$.region"}));
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the reviewed statement pack compiles");

    assert_eq!(
        run(&live.executor, json!({"region":"nw"}), EVALUATED_AT)
            .await
            .expect("the statement runs"),
        matched_rows(json!([{"id":"p-1"}, {"id":"p-2"}]))
    );
}

#[tokio::test]
async fn the_reserved_instant_reaches_the_statement_and_a_pinned_instant_repeats() {
    let plan = Plan::default()
        .statement("SELECT :evidence_now AS observed FROM person WHERE id = 'p-1'")
        .columns(&[("observed", "string")]);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the host-clock statement compiles");

    let first = run(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect("the statement runs");
    let second = run(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect("the statement runs again");

    // The runtime's own instant is what the statement saw, in the fixed-width
    // form the transport binds, so a pinned evaluation is reproducible.
    assert_eq!(
        first,
        matched_rows(json!([{"observed": "2026-08-07T03:00:00Z"}]))
    );
    assert_eq!(first, second);

    let later = run(&live.executor, json!({}), "2026-08-07T04:30:00Z")
        .await
        .expect("the statement runs at another instant");
    assert_eq!(
        later,
        matched_rows(json!([{"observed": "2026-08-07T04:30:00Z"}]))
    );
    assert_eq!(
        run(
            &live.executor,
            json!({"evidence_now":"2099-01-01T00:00:00Z"}),
            EVALUATED_AT,
        )
        .await,
        Err(PackSourceError::Inputs),
        "a caller cannot add the host-reserved clock to the closed route inputs"
    );
}

#[tokio::test]
async fn an_extract_older_than_the_source_allows_fails_before_a_row_is_read() {
    // Three rows against a bound of one, so reading any row has its own
    // distinct failure. Whichever failure comes back says which check ran first.
    let plan = Plan::default().rows(1).extract_age(3_600);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the age-bounded statement compiles");

    assert_eq!(
        run(&live.executor, json!({}), EVALUATED_AT).await,
        Err(PackSourceError::StatementResult),
        "a fresh extract reaches the distinct row-bound refusal"
    );

    assert_eq!(
        run(&live.executor, json!({}), "2026-08-07T04:00:01Z").await,
        Err(PackSourceError::ExtractStale),
        "staleness must be checked before the statement reads its first row"
    );

    // The same fact, asked the way startup asks it. Startup only says it out
    // loud; the refusal above is what withholds an answer, and readiness does
    // not consult either.
    assert_eq!(
        live.executor.extract_is_stale(instant(EVALUATED_AT)),
        Ok(false)
    );
    assert_eq!(
        live.executor
            .extract_is_stale(instant("2026-08-07T04:00:01Z")),
        Ok(true)
    );
}

/// A stale-extract diagnostic names the governed runtime binding an adopter can
/// act on, not publisher-controlled metadata read from the source.
#[tokio::test]
async fn a_stale_extract_names_only_its_governed_profile() {
    let plan = Plan::default().extract_age(3_600);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the age-bounded statement compiles");
    let endpoint = live
        .pack
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id.as_str() == "statement")
        .expect("the reviewed SQLite endpoint");
    assert_eq!(
        endpoint
            .sqlite_extract
            .as_ref()
            .expect("the SQLite declaration")
            .extract_profile
            .as_str(),
        EXTRACT_PROFILE
    );

    let stale = run(&live.executor, json!({}), "2026-08-07T04:00:01Z")
        .await
        .expect_err("a stale extract is refused");
    assert_eq!(stale, PackSourceError::ExtractStale);
    let rendered = format!("{stale:?} {stale}");
    assert!(
        !rendered.contains(EXTRACT_PROFILE),
        "the request-time category carried the governed extract profile: {rendered}"
    );
    assert!(
        !rendered.contains(&live.extract_path.display().to_string()),
        "the request-time category carried the extract path: {rendered}"
    );
    assert!(
        !rendered.contains("2026-08-07-full"),
        "the request-time category carried publisher metadata: {rendered}"
    );

    let diagnosed = live
        .executor
        .diagnose_extract_freshness(instant("2026-08-07T04:00:01Z"))
        .expect_err("operator preflight retains the stale-extract diagnosis");
    assert_eq!(diagnosed.category(), PackSourceError::ExtractStale);
    let diagnosed_rendered = format!("{diagnosed:?} {diagnosed}");
    assert!(!diagnosed_rendered.contains(EXTRACT_PROFILE));
    assert!(!diagnosed_rendered.contains(&live.extract_path.display().to_string()));
    assert!(!diagnosed_rendered.contains("2026-08-07-full"));
    let fault = diagnosed
        .artifact_fault()
        .expect("a stale extract names its governed profile");
    assert_eq!(fault.artifact(), EXTRACT_PROFILE);
    let operator_rendered = fault.to_string();
    assert!(operator_rendered.contains("adapter.sqlite.extract-stale"));
    assert!(!operator_rendered.contains(&live.extract_path.display().to_string()));
    assert!(!operator_rendered.contains("2026-08-07-full"));
}

#[tokio::test]
async fn declarative_parameter_bindings_bind_selector_values_by_type() {
    let plan = Plan::default()
        .statement("SELECT id FROM person WHERE region_code = :region AND rank = :rank")
        .input("region", "region_code", InputKind::String)
        .input("rank", "rank", InputKind::Integer)
        .parameter("region", json!({"jsonpath":"$.region"}))
        .parameter("rank", json!({"jsonpath":"$.rank"}));
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the typed-parameter statement compiles");
    let inputs = live
        .executor
        .inputs(&authorization(&[
            (
                "region_code",
                ResolvedSelectorValue::String("nw".to_owned()),
            ),
            ("rank", ResolvedSelectorValue::Integer(2)),
        ]))
        .expect("authorized selectors materialize the reviewed route inputs");
    assert_eq!(
        inputs,
        json!({"region":"nw", "rank":2}),
        "Evidence must preserve the selector field types at the pack boundary"
    );
    assert_eq!(
        run(&live.executor, inputs, EVALUATED_AT)
            .await
            .expect("the typed parameters reach SQLite"),
        matched_rows(json!([{"id":"p-2"}]))
    );
}

/// A prepared parameter carries a value a selector does not hold, produced by
/// the deployment's own script, and the statement runs on it.
#[tokio::test]
async fn a_prepared_parameter_takes_its_value_from_a_real_preparation_script() {
    let plan = Plan::default()
        .statement("SELECT id FROM person WHERE id = :reference")
        .input("recordReference", "record_reference", InputKind::String)
        .derived_parameter(
            "reference",
            "fn derive_reference(exchange) {\n  let reference = exchange.body.recordReference;\n  reference.replace(\"urn:example:person:\", \"\");\n  reference\n}",
            "derive_reference",
        );
    // The register stores the bare identifier and the caller presents a URN, so
    // the normalized form exists only because the script derived it. There is
    // no selector field whose value is the derived bare identifier.
    let live =
        compile_live(&plan, &extract_seed(PUBLISHED_AT)).expect("the pinned Rhai route compiles");
    assert_eq!(
        run(
            &live.executor,
            json!({"recordReference":"urn:example:person:p-3"}),
            EVALUATED_AT,
        )
        .await
        .expect("the Rhai-derived parameter reaches SQLite"),
        matched_rows(json!([{"id":"p-3"}]))
    );
}

/// A parameter has one declared route-expression origin and exactly one. The
/// endpoint declaration and route map agree on the complete set; missing and
/// undeclared origins fail with one closed category. The host-reserved clock's
/// non-overridability is exercised separately above.
#[tokio::test]
async fn a_parameter_is_filled_from_its_one_declared_origin() {
    let statement =
        "SELECT id FROM person WHERE region_code = :region AND rank <= :cutoff ORDER BY id";
    let plan = Plan::default()
        .statement(statement)
        .input("region", "region_code", InputKind::String)
        .input("cutoff", "rank", InputKind::Integer)
        .parameter("region", json!({"jsonpath":"$.region"}))
        .parameter("cutoff", json!({"jsonpath":"$.cutoff"}));
    let live =
        compile_live(&plan, &extract_seed(PUBLISHED_AT)).expect("the two-origin plan compiles");
    assert_eq!(
        run(
            &live.executor,
            json!({"region":"nw", "cutoff":1}),
            EVALUATED_AT,
        )
        .await
        .expect("each parameter is filled from its one declared expression"),
        matched_rows(json!([{"id":"p-1"}]))
    );

    let cases = [
        Plan::default()
            .statement(statement)
            .input("region", "region_code", InputKind::String)
            .input("cutoff", "rank", InputKind::Integer)
            .parameter("region", json!({"jsonpath":"$.region"}))
            .declared_parameter("cutoff"),
        Plan::default()
            .statement(statement)
            .input("region", "region_code", InputKind::String)
            .input("cutoff", "rank", InputKind::Integer)
            .parameter("region", json!({"jsonpath":"$.region"}))
            .parameter("cutoff", json!({"jsonpath":"$.cutoff"}))
            .route_parameter("undeclared", json!({"constant":1})),
    ];
    for refused in cases {
        let live = compile_live(&refused, &extract_seed(PUBLISHED_AT))
            .expect("the structurally reviewable refusal case compiles");
        assert_eq!(
            run(
                &live.executor,
                json!({"region":"nw", "cutoff":1}),
                EVALUATED_AT,
            )
            .await,
            Err(PackSourceError::StatementParameter)
        );
    }
}

#[tokio::test]
async fn a_refused_statement_names_the_artifact_and_a_closed_cause() {
    let plan = Plan::default()
        .statement("SELECT missing_column FROM person")
        .columns(&[("missing_column", "string")]);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the digest-pinned plan compiles before opening the captured schema");
    let endpoint = live
        .pack
        .endpoints
        .iter()
        .find(|endpoint| endpoint.id.as_str() == "statement")
        .expect("the reviewed SQLite endpoint");
    let declaration = endpoint
        .sqlite_extract
        .as_ref()
        .expect("the SQLite declaration");
    assert_eq!(declaration.statement.path.as_str(), STATEMENT_ARTIFACT);

    let (directory, captured, _path) = captured_extract(&extract_seed(PUBLISHED_AT));
    let lower_plan = SqliteExtractPlan::compile(endpoint, &live.artifacts)
        .expect("the offline statement shape is reviewable");
    let refusal = lower_plan
        .open(captured)
        .err()
        .expect("the captured schema refuses the unknown column");
    assert_eq!(
        refusal,
        SqliteExtractError::Statement(ErrorKind::UnknownColumn)
    );
    assert_eq!(refusal.code(), "adapter.sqlite.statement-refused");
    drop(directory);

    let evidence_error = run(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect_err("Evidence refuses the reviewed statement");
    assert_eq!(evidence_error, PackSourceError::StatementRefused);
    let rendered = format!("{evidence_error:?} {evidence_error}");
    assert!(
        !rendered.contains(STATEMENT_ARTIFACT),
        "the request-time category carried the governed statement artifact: {rendered}"
    );

    let diagnosed = run_diagnosed(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect_err("operator execution retains the statement diagnosis");
    assert_eq!(diagnosed.category(), PackSourceError::StatementRefused);
    let diagnosed_rendered = format!("{diagnosed:?} {diagnosed}");
    assert!(!diagnosed_rendered.contains(STATEMENT_ARTIFACT));
    let fault = diagnosed
        .artifact_fault()
        .expect("a refused statement names its governed artifact");
    assert_eq!(fault.artifact(), STATEMENT_ARTIFACT);
    assert!(fault
        .to_string()
        .contains("adapter.sqlite.statement-refused"));
}

#[tokio::test]
async fn no_rendering_carries_statement_text_or_extract_data() {
    let mut rendered = Vec::new();

    // A statement the engine cannot parse: its own message would quote the text
    // around the fault, and that text holds the canary.
    let broken_plan = Plan::default().statement(&format!(
        "SELECT id FROM person WHERE note = '{CANARY}' AND((("
    ));
    let broken = match compile_live(&broken_plan, &extract_seed(PUBLISHED_AT)) {
        Ok(_) => panic!("the malformed statement was accepted"),
        Err(error) => error,
    };
    rendered.push(format!("{broken:?} {broken}"));

    // A result value that overruns its cell bound: the value itself is extract
    // data carrying the canary.
    let plan = Plan::default()
        .statement("SELECT note AS id FROM person WHERE region_code = 'nw' ORDER BY id")
        .cell_bytes(8);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the cell-bounded statement compiles");
    let too_large = run(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect_err("the cell bound stops the result");
    rendered.push(format!("{too_large:?} {too_large}"));
    rendered.push(format!("{:?}", live.executor));

    for text in &rendered {
        assert!(!text.contains(CANARY), "a diagnostic carried data: {text}");
    }
}

#[tokio::test]
async fn a_source_compiled_without_an_extract_materializes_but_refuses_to_run() {
    let plan = Plan::default()
        .statement("SELECT id FROM person WHERE region_code = :region ORDER BY id")
        .input("region", "region_code", InputKind::String)
        .parameter("region", json!({"jsonpath":"$.region"}));
    let package = prepared_pack(&plan);
    let programs = compile_sources(&package.bundle)
        .expect("the offline pack plan compiles without runtime bindings");
    let program = programs
        .get("licence-register")
        .expect("the synthetic offline source");
    let run = program
        .execute_observed(
            &authorization(&[(
                "region_code",
                ResolvedSelectorValue::String("nw".to_owned()),
            )]),
            FixtureAcquisition {
                intercepts: Vec::new(),
                exchanges: Vec::new(),
            },
            None,
            instant(EVALUATED_AT),
        )
        .await;
    assert_eq!(
        run.outcome,
        Err(KernelError::Bundle),
        "an absent fixture extract is refused before route execution"
    );
    assert_eq!(run.data_operations, 0, "no statement was executed");
}

#[tokio::test]
async fn a_statement_source_needs_no_credentials() {
    let live = compile_live(&Plan::default(), &extract_seed(PUBLISHED_AT))
        .expect("the credential-free statement pack compiles");
    assert_eq!(live.executor.credentials_ready().await, Ok(()));
}

/// Operator diagnostics retain a reviewed artifact only for a failure that the
/// actual statement host attributes to it. Input refusal stays categorical.
#[tokio::test]
async fn only_artifact_bound_failures_expose_the_reviewed_artifact_fault() {
    let plan = Plan::default()
        .statement("SELECT missing_column FROM person")
        .columns(&[("missing_column", "string")]);
    let live = compile_live(&plan, &extract_seed(PUBLISHED_AT))
        .expect("the reviewed statement compiles before the captured schema is opened");
    let input_failure = run_diagnosed(
        &live.executor,
        json!({"undeclared_input": CANARY}),
        EVALUATED_AT,
    )
    .await
    .expect_err("undeclared route input is refused before source execution");
    assert_eq!(input_failure.category(), PackSourceError::Inputs);
    assert!(input_failure.artifact_fault().is_none());

    let statement_failure = run_diagnosed(&live.executor, json!({}), EVALUATED_AT)
        .await
        .expect_err("the captured schema refuses the undeclared result column");
    assert_eq!(
        statement_failure.category(),
        PackSourceError::StatementRefused
    );
    let artifact = statement_failure
        .artifact_fault()
        .expect("the host retains the reviewed statement artifact for an operator");
    assert_eq!(artifact.artifact(), STATEMENT_ARTIFACT);
    assert!(artifact
        .to_string()
        .contains("adapter.sqlite.statement-refused"));
    for failure in [&input_failure, &statement_failure] {
        let rendered = format!("{failure:?} {failure}");
        for protected in [CANARY, STATEMENT_ARTIFACT, "missing_column"] {
            assert!(!rendered.contains(protected));
        }
    }
}
