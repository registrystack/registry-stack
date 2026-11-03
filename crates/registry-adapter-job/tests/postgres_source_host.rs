// SPDX-License-Identifier: Apache-2.0

//! Operational proof for the job host's default-off PostgreSQL source.
//! The real `adapter-job` binary reads a bounded page from a disposable
//! PostgreSQL source, records identity only in its separate store, and hands
//! the declared projection through the destination seam. The two authored
//! destination kinds run separately so source hosting cannot accidentally
//! depend on either one. The loopback receiver is only a public seam fixture;
//! native BReg and Coordinator behavior is proven in their own suites.

#![cfg(all(feature = "job-postgres", feature = "postgres-test"))]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use registry_platform_config::{sha256_uri, SecretProvider, SecretResolver};
use serde_json::{json, Value};
use tokio_postgres::config::Host;

#[path = "support/fixture_receiver.rs"]
mod fixture_receiver;

use fixture_receiver::{FixtureReceiver, Scripted};

static UNIQUE_SUFFIX: AtomicU64 = AtomicU64::new(0);
static ACTUAL_POSTGRES_CASE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

struct RestoreEnvironment {
    name: &'static str,
    prior: Option<OsString>,
}

impl Drop for RestoreEnvironment {
    fn drop(&mut self) {
        match &self.prior {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

const PROFILE: &str = r#"apiVersion: id.registrystack.org/formats/adapter/profile/v1alpha1
kind: AdapterProfile
id: ledger
version: "1"
operations: []
problems:
  - code: ledger.upstream
    status: 502
    title: the source could not be reached
    classes: [upstream, breaker.open, throttle.rejected, loop.maximum-iterations-reached]
  - code: ledger.mapping
    status: 422
    title: the request or its mapping was refused
    classes: [validation, conversion.unmapped, aggregation.duplicate]
  - code: ledger.exhausted
    status: 502
    title: the run exhausted a budget
    classes: [script, budget.exhausted, outcome, facade]
  - code: ledger.boundary
    status: 500
    title: the facade refused the call
    classes: [disclosure.violation, egress.refused, credential.rejected]
problemEnvelope: '{"family": "{{problemCode}}"}'
"#;

const DIRECT_MAPPING: &str = r#"fn map_proposal(exchange) {
    #{startInput: #{input: exchange.body}, submitBody: #{}}
}
"#;

#[derive(Clone, Copy, Debug)]
enum DestinationKind {
    DirectBreg,
    SignedCoordinatorEvent,
}

#[derive(Clone, Copy, Debug)]
enum SourceQuery {
    Rows,
    ParameterizedRows,
    MissingParameter,
    ExtraParameter,
    IncompatibleParameter,
    EditableRow,
    UnusedSource,
    UndeclaredSource,
    SequenceWrite,
    OversizedField,
    OversizedRow,
    OversizedAggregate,
    FiniteFloatKey(FiniteSql),
    FiniteFloatValue(FiniteSql),
    NonFiniteKey(NonFiniteSql),
    NonFiniteValue(NonFiniteSql),
    /// One row whose status is NULL and whose note is the given SQL
    /// expression, so each native column type is read through the host.
    TypedNote(&'static str),
    NullKey,
}

#[derive(Clone, Copy, Debug)]
enum FiniteSql {
    Float4,
    Float8,
}

#[derive(Clone, Copy, Debug)]
enum NonFiniteSql {
    Float4Nan,
    Float4PositiveInfinity,
    Float4NegativeInfinity,
    Float8Nan,
    Float8PositiveInfinity,
    Float8NegativeInfinity,
}

impl NonFiniteSql {
    const fn type_name(self) -> &'static str {
        match self {
            Self::Float4Nan | Self::Float4PositiveInfinity | Self::Float4NegativeInfinity => "real",
            Self::Float8Nan | Self::Float8PositiveInfinity | Self::Float8NegativeInfinity => {
                "double precision"
            }
        }
    }

    const fn expression(self) -> &'static str {
        match self {
            Self::Float4Nan => "'NaN'::real",
            Self::Float4PositiveInfinity => "'Infinity'::real",
            Self::Float4NegativeInfinity => "'-Infinity'::real",
            Self::Float8Nan => "'NaN'::double precision",
            Self::Float8PositiveInfinity => "'Infinity'::double precision",
            Self::Float8NegativeInfinity => "'-Infinity'::double precision",
        }
    }
}

#[derive(Clone, Copy)]
struct SourceBounds {
    maximum_response_bytes: u64,
    maximum_row_bytes: u64,
    maximum_field_bytes: u64,
}

impl SourceQuery {
    const fn bounds(self) -> SourceBounds {
        match self {
            Self::Rows
            | Self::ParameterizedRows
            | Self::MissingParameter
            | Self::ExtraParameter
            | Self::IncompatibleParameter
            | Self::EditableRow
            | Self::UnusedSource
            | Self::UndeclaredSource
            | Self::SequenceWrite
            | Self::OversizedField
            | Self::FiniteFloatKey(_)
            | Self::FiniteFloatValue(_)
            | Self::NonFiniteKey(_)
            | Self::NonFiniteValue(_)
            | Self::TypedNote(_)
            | Self::NullKey => SourceBounds {
                maximum_response_bytes: 65_536,
                maximum_row_bytes: 4_096,
                maximum_field_bytes: 1_024,
            },
            Self::OversizedRow => SourceBounds {
                maximum_response_bytes: 65_536,
                maximum_row_bytes: 1_024,
                maximum_field_bytes: 512,
            },
            Self::OversizedAggregate => SourceBounds {
                maximum_response_bytes: 1_024,
                maximum_row_bytes: 800,
                maximum_field_bytes: 700,
            },
        }
    }

    const fn query_parameters(self) -> &'static str {
        match self {
            Self::ParameterizedRows | Self::UnusedSource => {
                "{startId: {constant: '001'}, minimumOrdinal: {constant: 1}, maximumOrdinal: {constant: 2.5}, enabled: {constant: true}}"
            }
            Self::MissingParameter => {
                "{startId: {constant: '001'}, minimumOrdinal: {constant: 1}, enabled: {constant: true}}"
            }
            Self::ExtraParameter => {
                "{startId: {constant: '001'}, minimumOrdinal: {constant: 1}, maximumOrdinal: {constant: 2.5}, enabled: {constant: true}, unexpected: {constant: 9}}"
            }
            Self::IncompatibleParameter => {
                "{startId: {constant: '001'}, minimumOrdinal: {constant: 'one'}, maximumOrdinal: {constant: 2.5}, enabled: {constant: true}}"
            }
            Self::Rows
            | Self::EditableRow
            | Self::UndeclaredSource
            | Self::SequenceWrite
            | Self::OversizedField
            | Self::OversizedRow
            | Self::OversizedAggregate
            | Self::FiniteFloatKey(_)
            | Self::FiniteFloatValue(_)
            | Self::NonFiniteKey(_)
            | Self::NonFiniteValue(_)
            | Self::TypedNote(_)
            | Self::NullKey => "{}",
        }
    }

    const fn parameter_order(self) -> &'static str {
        match self {
            Self::ParameterizedRows
            | Self::MissingParameter
            | Self::ExtraParameter
            | Self::IncompatibleParameter
            | Self::UnusedSource => {
                "    parameterOrder: [startId, minimumOrdinal, maximumOrdinal, enabled]\n"
            }
            Self::Rows
            | Self::EditableRow
            | Self::UndeclaredSource
            | Self::SequenceWrite
            | Self::OversizedField
            | Self::OversizedRow
            | Self::OversizedAggregate
            | Self::FiniteFloatKey(_)
            | Self::FiniteFloatValue(_)
            | Self::NonFiniteKey(_)
            | Self::NonFiniteValue(_)
            | Self::TypedNote(_)
            | Self::NullKey => "",
        }
    }

    const fn edits(self) -> &'static str {
        if matches!(
            self,
            Self::EditableRow | Self::FiniteFloatKey(_) | Self::FiniteFloatValue(_)
        ) {
            "rescan"
        } else {
            "ordered"
        }
    }

    const fn has_unused_source(self) -> bool {
        matches!(self, Self::UnusedSource)
    }

    const fn has_undeclared_source(self) -> bool {
        matches!(self, Self::UndeclaredSource)
    }
}

struct DatabaseBinding {
    base_url: String,
    host: String,
    port: u16,
    database: String,
    user: String,
    password: OsString,
}

impl DatabaseBinding {
    fn from_environment() -> Self {
        let base_url = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("ADAPTER_TEST_DATABASE_URL names a disposable PostgreSQL test server");
        let config = tokio_postgres::Config::from_str(&base_url)
            .expect("the disposable PostgreSQL URL parses");
        let host = match config.get_hosts().first() {
            Some(Host::Tcp(host)) => host.clone(),
            _ => panic!("the disposable PostgreSQL source uses a TCP host"),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        let database = config
            .get_dbname()
            .expect("the disposable PostgreSQL URL names a database")
            .to_owned();
        let user = config
            .get_user()
            .expect("the disposable PostgreSQL URL names a user")
            .to_owned();
        let password = config
            .get_password()
            .expect("the disposable PostgreSQL URL names a password");
        let password = String::from_utf8(password.to_vec())
            .expect("the disposable PostgreSQL password is text")
            .into();
        Self {
            base_url,
            host,
            port,
            database,
            user,
            password,
        }
    }
}

struct Fixture {
    _case_permit: tokio::sync::SemaphorePermit<'static>,
    _root: tempfile::TempDir,
    pack: PathBuf,
    job: PathBuf,
    profile: PathBuf,
    project: PathBuf,
    runtime: PathBuf,
    store_url: String,
    source_url: String,
    source_schema: String,
    source_password: OsString,
}

impl Fixture {
    async fn new(
        binding: &DatabaseBinding,
        destination: DestinationKind,
        query_kind: SourceQuery,
    ) -> Self {
        // The real CLI cases each own a database schema and loopback receiver.
        // Keep one active at a time so process and socket pressure cannot turn
        // a source assertion into a destination-fixture failure.
        let case_permit = ACTUAL_POSTGRES_CASE
            .acquire()
            .await
            .expect("the actual PostgreSQL case semaphore remains open");
        let root = tempfile::tempdir().expect("a postgres-source host fixture directory");
        let unique = unique_suffix();
        let source_schema = format!("adapter_job_source_{unique}");
        let store_schema = format!("adapter_job_store_{unique}");
        let (client, connection) =
            tokio_postgres::connect(&binding.base_url, tokio_postgres::NoTls)
                .await
                .expect("connect the disposable PostgreSQL server");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the disposable PostgreSQL connection failed: {error}");
            }
        });
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {source_schema};\
                 CREATE SCHEMA {store_schema};\
                 CREATE TABLE {source_schema}.submissions (\
                   ordinal bigint PRIMARY KEY, external_id text NOT NULL,\
                   status text NOT NULL, note text NOT NULL,\
                   real_value real NOT NULL, double_value double precision NOT NULL\
                 );\
                 INSERT INTO {source_schema}.submissions VALUES\
                   (1, '001', 'new', 'first', 1.25, 2.5),\
                   (2, '002', 'ready', 'second', 3.25, 4.5),\
                   (3, '003', 'held', 'beyond-page-bound', 5.25, 6.5);\
                 CREATE SEQUENCE {source_schema}.source_sequence"
            ))
            .await
            .expect("seed the isolated PostgreSQL source and store schemas");

        let query = match query_kind {
            SourceQuery::Rows => format!(
                "SELECT external_id AS id, status, note \
                 FROM {source_schema}.submissions ORDER BY ordinal"
            ),
            SourceQuery::UndeclaredSource => format!(
                "SELECT external_id AS id, status, note \
                 FROM {source_schema}.submissions ORDER BY ordinal"
            ),
            SourceQuery::ParameterizedRows
            | SourceQuery::MissingParameter
            | SourceQuery::ExtraParameter
            | SourceQuery::IncompatibleParameter
            | SourceQuery::UnusedSource => format!(
                "SELECT external_id AS id, status, note \
                 FROM {source_schema}.submissions \
                 WHERE external_id >= $1::text AND ordinal >= $2::integer \
                 AND ordinal::double precision <= $3::double precision AND $4::boolean \
                 ORDER BY ordinal"
            ),
            SourceQuery::EditableRow => format!(
                "SELECT external_id AS id, status, note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::SequenceWrite => format!(
                "SELECT nextval('{source_schema}.source_sequence') AS id, \
                 'new'::text AS status, 'write-attempt'::text AS note ORDER BY id"
            ),
            SourceQuery::OversizedField => "SELECT '001'::text AS id, 'new'::text AS status, \
                 repeat('x', 2048) AS note ORDER BY id"
                .to_owned(),
            SourceQuery::OversizedRow => {
                "SELECT repeat('1', 400) AS id, repeat('s', 400) AS status, \
                 repeat('n', 400) AS note ORDER BY id"
                    .to_owned()
            }
            SourceQuery::OversizedAggregate => {
                "SELECT ordinal::text AS id, 'new'::text AS status, \
                 repeat('n', 600) AS note FROM generate_series(1, 2) AS ordinal \
                 ORDER BY ordinal"
                    .to_owned()
            }
            SourceQuery::FiniteFloatKey(FiniteSql::Float4) => format!(
                "SELECT real_value AS id, status, double_value AS note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::FiniteFloatKey(FiniteSql::Float8) => format!(
                "SELECT double_value AS id, status, real_value AS note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::FiniteFloatValue(FiniteSql::Float4) => format!(
                "SELECT external_id AS id, status, real_value AS note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::FiniteFloatValue(FiniteSql::Float8) => format!(
                "SELECT external_id AS id, status, double_value AS note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::NonFiniteKey(value) => format!(
                "SELECT id, status, note FROM (VALUES \
                 (1, 0.5::{}, 'valid'::text, 'valid'::text), \
                 (2, {}, 'bad'::text, 'bad'::text)) \
                 AS source(ordinal, id, status, note) ORDER BY ordinal",
                value.type_name(),
                value.expression()
            ),
            SourceQuery::NonFiniteValue(value) => format!(
                "SELECT id, status, note FROM (VALUES \
                 (1, '001'::text, 'valid'::text, 0.5::{}), \
                 (2, '002'::text, 'bad'::text, {})) \
                 AS source(ordinal, id, status, note) ORDER BY ordinal",
                value.type_name(),
                value.expression()
            ),
            SourceQuery::TypedNote(expression) => format!(
                "SELECT external_id AS id, NULL::text AS status, {expression} AS note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
            SourceQuery::NullKey => format!(
                "SELECT NULL::text AS id, status, note \
                 FROM {source_schema}.submissions WHERE ordinal = 1 ORDER BY ordinal"
            ),
        };
        let bounds = query_kind.bounds();
        let pack_text = pack_yaml(&query, bounds, query_kind);
        let pack_digest = sha256_uri(pack_text.as_bytes());
        let profile_digest = sha256_uri(PROFILE.as_bytes());
        let pack = root.path().join("pack.yaml");
        let job = root.path().join("job.yaml");
        let profile = root.path().join("profile.yaml");
        let project = root.path().join("project.yaml");
        let runtime = root.path().join("runtime.yaml");
        std::fs::create_dir(root.path().join("queries")).expect("the queries directory");
        std::fs::create_dir(root.path().join("mappings")).expect("the mappings directory");
        std::fs::write(root.path().join("queries/source.sql"), &query).expect("the pinned query");
        std::fs::write(root.path().join("mappings/direct.rhai"), DIRECT_MAPPING)
            .expect("the direct destination mapping");
        std::fs::write(&pack, &pack_text).expect("the pack");
        std::fs::write(&profile, PROFILE).expect("the profile");
        std::fs::write(&project, project_yaml(&profile_digest, &pack_digest)).expect("the project");
        std::fs::write(&job, job_yaml(&pack_digest, destination, bounds)).expect("the job");
        std::fs::write(&runtime, runtime_yaml(binding, query_kind)).expect("the runtime config");

        let separator = if binding.base_url.contains('?') {
            '&'
        } else {
            '?'
        };
        let store_url = format!(
            "{}{separator}options=-csearch_path%3D{}",
            binding.base_url, store_schema
        );
        tokio_postgres::Config::from_str(&store_url).expect("the isolated store URL parses");
        Self {
            _case_permit: case_permit,
            _root: root,
            pack,
            job,
            profile,
            project,
            runtime,
            store_url,
            source_url: binding.base_url.clone(),
            source_schema,
            source_password: binding.password.clone(),
        }
    }

    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_adapter-job"));
        command
            .env("JOB_TEST_DB", &self.store_url)
            .env("JOB_SOURCE_PASSWORD", &self.source_password)
            .arg(subcommand)
            .arg(&self.job)
            .arg("--pack")
            .arg(&self.pack)
            .arg("--runtime")
            .arg(&self.runtime);
        command
    }

    async fn update_first_row(&self) {
        let (client, connection) = tokio_postgres::connect(&self.source_url, tokio_postgres::NoTls)
            .await
            .expect("connect the isolated source for one reviewed edit");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the disposable PostgreSQL connection failed: {error}");
            }
        });
        client
            .execute(
                &format!(
                    "UPDATE {}.submissions SET status = 'revised', note = 'edited' WHERE ordinal = 1",
                    self.source_schema
                ),
                &[],
            )
            .await
            .expect("edit the isolated source row");
    }

    async fn update_first_float_row(&self, query_kind: SourceQuery) {
        let assignment = match query_kind {
            SourceQuery::FiniteFloatKey(_) => "status = 'revised'",
            SourceQuery::FiniteFloatValue(FiniteSql::Float4) => "real_value = 1.5",
            SourceQuery::FiniteFloatValue(FiniteSql::Float8) => "double_value = 2.75",
            _ => panic!("a finite-float query kind is required"),
        };
        let (client, connection) = tokio_postgres::connect(&self.source_url, tokio_postgres::NoTls)
            .await
            .expect("connect the isolated source for one finite-float edit");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the disposable PostgreSQL connection failed: {error}");
            }
        });
        client
            .execute(
                &format!(
                    "UPDATE {}.submissions SET {assignment} WHERE ordinal = 1",
                    self.source_schema
                ),
                &[],
            )
            .await
            .expect("edit the isolated finite-float source row");
    }

    async fn item_count(&self) -> i64 {
        let (client, connection) = tokio_postgres::connect(&self.store_url, tokio_postgres::NoTls)
            .await
            .expect("connect the isolated item store");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the disposable PostgreSQL connection failed: {error}");
            }
        });
        client
            .query_one(
                "SELECT count(*) FROM adapter_job_items WHERE job_id = 'ledger-daily'",
                &[],
            )
            .await
            .expect("count the isolated job items")
            .get(0)
    }

    async fn sequence_unchanged(&self) -> bool {
        let (client, connection) = tokio_postgres::connect(&self.source_url, tokio_postgres::NoTls)
            .await
            .expect("connect the isolated source sequence");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                panic!("the disposable PostgreSQL connection failed: {error}");
            }
        });
        client
            .query_one(
                &format!(
                    "SELECT NOT is_called FROM {}.source_sequence",
                    self.source_schema
                ),
                &[],
            )
            .await
            .expect("read the isolated source sequence state")
            .get(0)
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the test clock is after the Unix epoch")
        .as_nanos();
    let counter = UNIQUE_SUFFIX.fetch_add(1, Ordering::Relaxed);
    format!("{nanos}_{counter}")
}

fn pack_yaml(query: &str, bounds: SourceBounds, query_kind: SourceQuery) -> String {
    let unused_endpoint = if query_kind.has_unused_source() {
        format!(
            r#"  - id: unused-ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 1000
    maximumResponseBytes: 65536
    queryFile: queries/source.sql
    keyColumn: id
{}"#,
            query_kind.parameter_order()
        )
    } else {
        String::new()
    };
    let unused_route = if query_kind.has_unused_source() {
        r#"  - id: unused-page
    scan: finite
    nextRecovery: key-deduplicated
    edits: ordered
    steps:
      - to:
          uri: postgres:unused-ledger
          parameters:
            queryParameters: {}
"#
    } else {
        ""
    };
    let rescan_delay = if query_kind.edits() == "rescan" {
        "    rescanDelaySeconds: 60\n"
    } else {
        ""
    };
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/pack/v1alpha1
kind: AdapterPack
id: ledger-pack
version: "1"
testedVersions: []
endpoints:
  - id: ledger
    component: postgres
    authentication:
      type: none
    attemptTimeoutMilliseconds: 1000
    maximumResponseBytes: {}
    queryFile: queries/source.sql
    keyColumn: id
{}{unused_endpoint}queryFiles:
  - path: queries/source.sql
    digest: {}
sourceRoutes:
  - id: ledger-page
    scan: finite
    nextRecovery: key-deduplicated
    edits: {}
{rescan_delay}    steps:
      - to:
          uri: postgres:ledger
          parameters:
            queryParameters: {}
{unused_route}capabilities: {{}}
"#,
        bounds.maximum_response_bytes,
        query_kind.parameter_order(),
        sha256_uri(query.as_bytes()),
        query_kind.edits(),
        query_kind.query_parameters(),
    )
}

fn project_yaml(profile_digest: &str, pack_digest: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/project/v1alpha1
kind: AdapterProject
project:
  id: ledger-example
  version: "1"
profile:
  id: ledger
  version: "1"
  digest: {profile_digest}
pack:
  id: ledger-pack
  version: "1"
  digest: {pack_digest}
recordTypes: []
bindings: []
"#
    )
}

fn job_yaml(pack_digest: &str, destination: DestinationKind, bounds: SourceBounds) -> String {
    let destination = match destination {
        DestinationKind::DirectBreg => format!(
            r#"destination:
  type: direct-breg
  binding: breg-test
  accessProfile: writer
  action: register-case
  mode: proposal
  mapping:
    file: mappings/direct.rhai
    entrypoint: map_proposal
    digest: {}
  receiptRetentionDays: 7"#,
            sha256_uri(DIRECT_MAPPING.as_bytes())
        ),
        DestinationKind::SignedCoordinatorEvent => r#"destination:
  type: signed-coordinator-event
  binding: coordinator-test
  workflow: case-ingestion
  trigger: submitted
  source: urn:registry-adapter:job:ledger-daily
  eventType: org.example.case-submitted.v1
  dataSchema: urn:example:schema:case-submitted:v1"#
            .to_owned(),
    };
    format!(
        r#"apiVersion: id.registrystack.org/formats/adapter/job/v1alpha1
kind: AdapterJob
job:
  id: ledger-daily
  version: "1"
source:
  pack:
    id: ledger-pack
    version: "1"
    digest: {pack_digest}
  route: ledger-page
{destination}
projection:
  fields: [id, status, note]
triggers:
  - kind: interval
    delayMilliseconds: 60000
profile:
  pageDeadlineMilliseconds: 5000
  maximumResponseBytes: {}
  maximumPageItems: 2
  maximumPageBytes: {}
  maximumUpstreamCalls: 1
  read:
    maximumFileBytes: 1048576
    maximumRowBytes: {}
    maximumFieldBytes: {}
    maximumRowsPerPage: 2
"#,
        bounds.maximum_response_bytes,
        bounds.maximum_response_bytes,
        bounds.maximum_row_bytes,
        bounds.maximum_field_bytes,
    )
}

fn runtime_yaml(binding: &DatabaseBinding, query_kind: SourceQuery) -> String {
    let mut postgres_sources = serde_json::Map::from_iter([(
        "ledger".to_owned(),
        json!({
            "host": binding.host,
            "port": binding.port,
            "database": binding.database,
            "user": binding.user,
            "passwordRef": "secret:env/JOB_SOURCE_PASSWORD",
            "namespace": "ledger",
            "tls": {"type": "plaintext"}
        }),
    )]);
    if query_kind.has_unused_source() {
        postgres_sources.insert(
            "unused-ledger".to_owned(),
            json!({
                "host": binding.host,
                "port": binding.port,
                "database": binding.database,
                "user": binding.user,
                "passwordRef": "secret:env/JOB_SOURCE_PASSWORD_UNUSED",
                "namespace": "unused-ledger",
                "tls": {"type": "plaintext"}
            }),
        );
    }
    if query_kind.has_undeclared_source() {
        postgres_sources.insert(
            "undeclared-ledger".to_owned(),
            json!({
                "host": binding.host,
                "port": binding.port,
                "database": binding.database,
                "user": binding.user,
                "passwordRef": "secret:env/JOB_SOURCE_PASSWORD_UNUSED",
                "namespace": "undeclared-ledger",
                "tls": {"type": "plaintext"}
            }),
        );
    }
    serde_json::to_string_pretty(&json!({
        "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
        "kind": "AdapterJobRuntimeConfig",
        "id": "ledger-job-test",
        "endpoints": [],
        "sources": {"postgres": postgres_sources},
        "allowedPrivateCidrs": ["127.0.0.0/8"],
        "store": {
            "runtimeUrlRef": "secret:env/JOB_TEST_DB",
            "testOnlyPlaintext": true
        },
        "destinations": {
            "coordinator-test": {
                "type": "signed-coordinator-event",
                "baseUrl": "http://127.0.0.1:9/events",
                "signingKeyRef": "secret:env/JOB_TEST_SIGNING_KEY",
                "attemptTimeoutMilliseconds": 1000
            }
        }
    }))
    .expect("the runtime config renders")
}

fn run_check(fixture: &Fixture) -> std::process::Output {
    fixture
        .command("check")
        .output()
        .expect("run adapter-job check")
}

async fn run_pass(fixture: &Fixture, receiver: &FixtureReceiver) -> std::process::Output {
    let mut command = fixture.command("pass");
    command
        .arg("--fixture")
        .arg("--fixture-url")
        .arg(&receiver.url);
    tokio::task::spawn_blocking(move || command.output().expect("run adapter-job pass"))
        .await
        .expect("the adapter-job pass joins")
}

async fn run_rescan(fixture: &Fixture, receiver: &FixtureReceiver) -> std::process::Output {
    let mut command = fixture.command("rescan");
    command
        .arg("--fixture")
        .arg("--fixture-url")
        .arg(&receiver.url);
    tokio::task::spawn_blocking(move || command.output().expect("run adapter-job rescan"))
        .await
        .expect("the adapter-job rescan joins")
}

#[tokio::test]
async fn actual_check_accepts_the_default_off_postgres_source_host() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::Rows,
    )
    .await;
    let output = run_check(&fixture);
    assert!(
        output.status.success(),
        "postgres-source check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("the check report is JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["source"]["route"], "ledger-page");
}

#[tokio::test]
async fn actual_postgres_page_reaches_both_destination_seams_with_all_bounds_intact() {
    let database = DatabaseBinding::from_environment();
    for destination in [
        DestinationKind::DirectBreg,
        DestinationKind::SignedCoordinatorEvent,
    ] {
        let fixture = Fixture::new(&database, destination, SourceQuery::Rows).await;
        let receiver = FixtureReceiver::start(vec![
            Scripted::Acknowledge { run_id: None },
            Scripted::Acknowledge { run_id: None },
        ])
        .await;
        let output = run_pass(&fixture, &receiver).await;
        assert!(
            output.status.success(),
            "{destination:?} postgres pass failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("the pass report is JSON");
        assert_eq!(
            report["itemsRead"], 2,
            "the row bound stops the source page"
        );
        assert_eq!(report["itemsAcknowledged"], 2);
        let requests = receiver.requests();
        assert_eq!(requests.len(), 2, "two bounded rows cross the seam");
        let first: Value =
            serde_json::from_slice(&requests[0].body).expect("the first delivery is JSON");
        let second: Value =
            serde_json::from_slice(&requests[1].body).expect("the second delivery is JSON");
        assert_eq!(
            first["projected"],
            json!({"id": "001", "status": "new", "note": "first"})
        );
        assert_eq!(
            second["projected"],
            json!({"id": "002", "status": "ready", "note": "second"})
        );
    }
}

#[tokio::test]
async fn actual_host_transaction_refuses_a_select_with_a_write_effect() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::SequenceWrite,
    )
    .await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let output = run_pass(&fixture, &receiver).await;
    assert!(
        !output.status.success(),
        "a sequence write through SELECT must fail in the host's read-only transaction"
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
    assert_eq!(report["stopped"]["reason"], "page-fault");
    assert!(
        receiver.requests().is_empty(),
        "a source read with a write effect reaches no destination"
    );
    assert!(
        fixture.sequence_unchanged().await,
        "the refused read-only SELECT leaves the source sequence untouched"
    );
}

#[tokio::test]
async fn actual_host_refuses_field_row_and_aggregate_byte_overruns_before_delivery() {
    let database = DatabaseBinding::from_environment();
    for query_kind in [
        SourceQuery::OversizedField,
        SourceQuery::OversizedRow,
        SourceQuery::OversizedAggregate,
    ] {
        let fixture = Fixture::new(
            &database,
            DestinationKind::SignedCoordinatorEvent,
            query_kind,
        )
        .await;
        let receiver = FixtureReceiver::start(vec![
            Scripted::Acknowledge { run_id: None },
            Scripted::Acknowledge { run_id: None },
        ])
        .await;
        let output = run_pass(&fixture, &receiver).await;
        assert!(
            !output.status.success(),
            "a postgres source byte overrun must fail before delivery"
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
        assert_eq!(
            report["stopped"]["code"], "page-fault:upstream.too-large",
            "the host classifies every source byte overrun without source values"
        );
        assert!(
            receiver.requests().is_empty(),
            "an over-bound source read reaches no destination"
        );
    }
}

async fn assert_finite_float_result_is_retained(query_kind: SourceQuery) {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        query_kind,
    )
    .await;
    let first_receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let first_output = run_pass(&fixture, &first_receiver).await;
    assert!(
        first_output.status.success(),
        "a finite PostgreSQL float result must be accepted: {query_kind:?}: stderr={} stdout={}",
        String::from_utf8_lossy(&first_output.stderr),
        String::from_utf8_lossy(&first_output.stdout)
    );
    let first_report: Value =
        serde_json::from_slice(&first_output.stdout).expect("the finite-float pass report is JSON");
    assert_eq!(first_report["itemsRead"], 1);
    assert_eq!(first_report["itemsAcknowledged"], 1);
    let first_requests = first_receiver.requests();
    assert_eq!(first_requests.len(), 1);
    let first_request: Value = serde_json::from_slice(&first_requests[0].body)
        .expect("the first finite-float delivery is JSON");
    let (first_projected, edited_projected) = match query_kind {
        SourceQuery::FiniteFloatKey(FiniteSql::Float4) => (
            json!({"id": 1.25, "status": "new", "note": 2.5}),
            json!({"id": 1.25, "status": "revised", "note": 2.5}),
        ),
        SourceQuery::FiniteFloatKey(FiniteSql::Float8) => (
            json!({"id": 2.5, "status": "new", "note": 1.25}),
            json!({"id": 2.5, "status": "revised", "note": 1.25}),
        ),
        SourceQuery::FiniteFloatValue(FiniteSql::Float4) => (
            json!({"id": "001", "status": "new", "note": 1.25}),
            json!({"id": "001", "status": "new", "note": 1.5}),
        ),
        SourceQuery::FiniteFloatValue(FiniteSql::Float8) => (
            json!({"id": "001", "status": "new", "note": 2.5}),
            json!({"id": "001", "status": "new", "note": 2.75}),
        ),
        _ => panic!("a finite-float query kind is required"),
    };
    assert_eq!(first_request["projected"], first_projected);
    assert_eq!(first_request["sequence"], 1);
    assert_eq!(fixture.item_count().await, 1);

    fixture.update_first_float_row(query_kind).await;
    let edit_receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let edit_output = run_rescan(&fixture, &edit_receiver).await;
    assert!(
        edit_output.status.success(),
        "an edited finite PostgreSQL float result must be accepted: {query_kind:?}: stderr={} stdout={}",
        String::from_utf8_lossy(&edit_output.stderr),
        String::from_utf8_lossy(&edit_output.stdout)
    );
    let edit_report: Value = serde_json::from_slice(&edit_output.stdout)
        .expect("the finite-float rescan report is JSON");
    assert_eq!(edit_report["itemsNew"], 0);
    assert_eq!(edit_report["itemsChanged"], 1);
    assert_eq!(edit_report["itemsAcknowledged"], 1);
    let edit_requests = edit_receiver.requests();
    assert_eq!(edit_requests.len(), 1);
    let edit_request: Value = serde_json::from_slice(&edit_requests[0].body)
        .expect("the edited finite-float delivery is JSON");
    assert_eq!(edit_request["projected"], edited_projected);
    assert_eq!(edit_request["key"], first_request["key"]);
    assert_eq!(edit_request["sequence"], 2);
    assert_ne!(edit_request["digest"], first_request["digest"]);
    assert_eq!(fixture.item_count().await, 1);
}

macro_rules! finite_float_host_case {
    ($name:ident, $query:expr) => {
        #[tokio::test]
        async fn $name() {
            assert_finite_float_result_is_retained($query).await;
        }
    };
}

finite_float_host_case!(
    actual_host_accepts_finite_float4_key_across_revision,
    SourceQuery::FiniteFloatKey(FiniteSql::Float4)
);
finite_float_host_case!(
    actual_host_accepts_finite_float8_key_across_revision,
    SourceQuery::FiniteFloatKey(FiniteSql::Float8)
);
finite_float_host_case!(
    actual_host_accepts_finite_float4_value_across_revision,
    SourceQuery::FiniteFloatValue(FiniteSql::Float4)
);
finite_float_host_case!(
    actual_host_accepts_finite_float8_value_across_revision,
    SourceQuery::FiniteFloatValue(FiniteSql::Float8)
);

async fn assert_non_finite_result_refuses(query_kind: SourceQuery) {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        query_kind,
    )
    .await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let output = run_pass(&fixture, &receiver).await;
    assert!(
        !output.status.success(),
        "a non-finite PostgreSQL result must fail closed: {query_kind:?}"
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
    assert_eq!(report["stopped"]["code"], "page-fault:upstream.malformed");
    assert!(
        receiver.requests().is_empty(),
        "a non-finite result reaches no destination: {query_kind:?}"
    );
    assert_eq!(
        fixture.item_count().await,
        0,
        "a valid row before a non-finite row is not partially retained: {query_kind:?}"
    );
}

macro_rules! non_finite_host_case {
    ($name:ident, $query:expr) => {
        #[tokio::test]
        async fn $name() {
            assert_non_finite_result_refuses($query).await;
        }
    };
}

non_finite_host_case!(
    actual_host_refuses_float4_nan_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float4Nan)
);
non_finite_host_case!(
    actual_host_refuses_float4_positive_infinity_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float4PositiveInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float4_negative_infinity_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float4NegativeInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float8_nan_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float8Nan)
);
non_finite_host_case!(
    actual_host_refuses_float8_positive_infinity_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float8PositiveInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float8_negative_infinity_key_before_delivery,
    SourceQuery::NonFiniteKey(NonFiniteSql::Float8NegativeInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float4_nan_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float4Nan)
);
non_finite_host_case!(
    actual_host_refuses_float4_positive_infinity_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float4PositiveInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float4_negative_infinity_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float4NegativeInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float8_nan_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float8Nan)
);
non_finite_host_case!(
    actual_host_refuses_float8_positive_infinity_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float8PositiveInfinity)
);
non_finite_host_case!(
    actual_host_refuses_float8_negative_infinity_value_before_delivery,
    SourceQuery::NonFiniteValue(NonFiniteSql::Float8NegativeInfinity)
);

#[tokio::test]
async fn actual_named_parameters_bind_text_integer_float_and_boolean_values() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::ParameterizedRows,
    )
    .await;
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge { run_id: None },
    ])
    .await;
    let output = run_pass(&fixture, &receiver).await;
    assert!(
        output.status.success(),
        "reviewed named parameters failed: stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the parameterized pass report is JSON");
    assert_eq!(report["itemsRead"], 2);
    assert_eq!(report["itemsAcknowledged"], 2);
    assert_eq!(receiver.requests().len(), 2);
}

#[tokio::test]
async fn actual_named_parameters_refuse_missing_extra_and_incompatible_values() {
    let database = DatabaseBinding::from_environment();
    for (query_kind, expected_code) in [
        (SourceQuery::MissingParameter, "page-fault:egress.refused"),
        (SourceQuery::ExtraParameter, "page-fault:egress.refused"),
        (SourceQuery::IncompatibleParameter, "page-fault:upstream"),
    ] {
        let fixture = Fixture::new(
            &database,
            DestinationKind::SignedCoordinatorEvent,
            query_kind,
        )
        .await;
        let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
        let output = run_pass(&fixture, &receiver).await;
        assert!(
            !output.status.success(),
            "an invalid named parameter set must fail closed"
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
        assert_eq!(report["stopped"]["code"], expected_code);
        assert!(
            receiver.requests().is_empty(),
            "an invalid named parameter set reaches no destination"
        );
    }
}

#[tokio::test]
async fn actual_source_edit_retains_key_and_advances_one_item_sequence() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::EditableRow,
    )
    .await;
    let first_receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let first_output = run_pass(&fixture, &first_receiver).await;
    assert!(
        first_output.status.success(),
        "the initial source pass failed: {}",
        String::from_utf8_lossy(&first_output.stderr)
    );
    let first_requests = first_receiver.requests();
    assert_eq!(first_requests.len(), 1);
    let first_request: Value =
        serde_json::from_slice(&first_requests[0].body).expect("the first delivery is JSON");
    assert_eq!(first_request["sequence"], 1);

    fixture.update_first_row().await;
    let edit_receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let edit_output = run_rescan(&fixture, &edit_receiver).await;
    assert!(
        edit_output.status.success(),
        "the edited source rescan failed: {}",
        String::from_utf8_lossy(&edit_output.stderr)
    );
    let edit_report: Value =
        serde_json::from_slice(&edit_output.stdout).expect("the rescan report is JSON");
    assert_eq!(edit_report["itemsNew"], 0);
    assert_eq!(edit_report["itemsChanged"], 1);
    assert_eq!(edit_report["itemsAcknowledged"], 1);
    let edited_requests = edit_receiver.requests();
    assert_eq!(edited_requests.len(), 1);
    let edited_request: Value =
        serde_json::from_slice(&edited_requests[0].body).expect("the edited delivery is JSON");
    assert_eq!(edited_request["key"], first_request["key"]);
    assert_eq!(edited_request["sequence"], 2);
    assert_eq!(edited_request["projected"]["status"], "revised");
    let format = registry_platform_yaml::FormatSpec {
        kind: registry_adapter_core::ADAPTER_PACK_KIND,
        envelope: registry_platform_yaml::EnvelopeRule::ApiVersionKind {
            api_versions: &[registry_platform_yaml::ApiVersion::current(
                registry_adapter_core::ADAPTER_PACK_API_VERSION,
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };
    let source_pack: Value = registry_platform_yaml::Reader::new("pack.yaml")
        .decode::<Value>(
            &std::fs::read(&fixture.pack).expect("read the mutable source contract"),
            &registry_platform_yaml::Expect::one(&format),
        )
        .expect("the mutable source contract is YAML")
        .value;
    assert_eq!(
        source_pack.pointer("/sourceRoutes/0/nextRecovery"),
        Some(&json!("key-deduplicated")),
        "a mutable SQL query without a snapshot cannot promise the same bytes on replay"
    );
    assert_eq!(fixture.item_count().await, 1);
}

#[tokio::test]
async fn actual_unused_route_credential_is_never_resolved() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::UnusedSource,
    )
    .await;
    let receiver = FixtureReceiver::start(vec![
        Scripted::Acknowledge { run_id: None },
        Scripted::Acknowledge { run_id: None },
    ])
    .await;
    let output = run_pass(&fixture, &receiver).await;
    assert!(
        output.status.success(),
        "an unreachable source credential was resolved: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(receiver.requests().len(), 2);
}

#[tokio::test]
async fn actual_check_refuses_an_undeclared_runtime_source_binding() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::UndeclaredSource,
    )
    .await;
    let output = run_check(&fixture);
    assert!(
        !output.status.success(),
        "a runtime PostgreSQL binding absent from the reviewed pack must refuse"
    );
    assert!(
        output.stdout.is_empty(),
        "a refused check emits no success report"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("adapter.job.source-unbound"),
        "the refusal names the closed source-binding diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn compiled_source_authority_survives_runtime_file_replacement() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::Rows,
    )
    .await;
    let _restore = RestoreEnvironment {
        name: "JOB_SOURCE_PASSWORD",
        prior: std::env::var_os("JOB_SOURCE_PASSWORD"),
    };
    std::env::set_var("JOB_SOURCE_PASSWORD", &fixture.source_password);
    let mut program = registry_adapter_engine::job::compile_job_with(
        &fixture.pack,
        &fixture.job,
        &fixture.runtime,
        &fixture.profile,
        &fixture.project,
    )
    .expect("the source authority compiles from one runtime snapshot");
    std::fs::write(&fixture.runtime, b"replaced after compile")
        .expect("replace the runtime path after compile");
    let resolver = SecretResolver::new([SecretProvider::Environment], "")
        .expect("the source secret resolver starts");
    registry_adapter_job::postgres_source::activate_postgres_sources(&mut program, &resolver)
        .expect("activation consumes the compiled snapshot, not the replaced file");
    let page = registry_adapter_engine::job::run_job_page(&program, None)
        .await
        .expect("the captured source authority reads the original database");
    assert_eq!(page.page.items.len(), 2);
}

// With three rows and a two-row page, a correct offset cursor reads row 003
// on the second pass. Prints each pass's report and the delivered ids, then
// asserts that row 003 was delivered.
#[tokio::test]
async fn a_two_row_page_over_three_rows_delivers_the_third_row_on_the_second_pass() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::Rows,
    )
    .await;
    let mut delivered = Vec::new();
    for pass in 1..=3 {
        let receiver = FixtureReceiver::start(vec![
            Scripted::Acknowledge { run_id: None },
            Scripted::Acknowledge { run_id: None },
            Scripted::Acknowledge { run_id: None },
        ])
        .await;
        let output = run_pass(&fixture, &receiver).await;
        let ids: Vec<Value> = receiver
            .requests()
            .iter()
            .map(|request| {
                let body: Value = serde_json::from_slice(&request.body).expect("delivery is JSON");
                body["projected"]["id"].clone()
            })
            .collect();
        println!(
            "second-page pass {pass}: exit={:?} delivered={ids:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim(),
        );
        delivered.extend(ids);
    }
    let items = fixture.item_count().await;
    println!("second-page stored items after three passes: {items}");
    assert!(
        delivered.contains(&json!("003")),
        "row 003 never crossed the seam in three passes: {delivered:?}"
    );
}

async fn typed_note_pass(expression: &'static str) -> (std::process::Output, Vec<Value>) {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::TypedNote(expression),
    )
    .await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let output = run_pass(&fixture, &receiver).await;
    let projected = receiver
        .requests()
        .iter()
        .map(|request| {
            let body: Value = serde_json::from_slice(&request.body).expect("delivery is JSON");
            body["projected"].clone()
        })
        .collect();
    (output, projected)
}

#[tokio::test]
async fn actual_host_reads_null_date_time_uuid_and_numeric_columns_as_canonical_values() {
    for (expression, expected) in [
        ("DATE '2026-11-03'", json!("2026-11-03")),
        (
            "TIMESTAMPTZ '2026-11-03 10:15:30.25+02'",
            json!("2026-11-03T08:15:30.250Z"),
        ),
        (
            "TIMESTAMP '2026-11-03 10:15:30'",
            json!("2026-11-03T10:15:30"),
        ),
        (
            "'A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11'::uuid",
            json!("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
        ),
        ("12345.6700::numeric(12,4)", json!("12345.6700")),
        ("(-0.0001)::numeric", json!("-0.0001")),
        ("100000::numeric", json!("100000")),
        ("0::numeric(6,2)", json!("0.00")),
        ("0.00000001::numeric", json!("0.00000001")),
        ("(-98765432.1)::numeric", json!("-98765432.1")),
        ("NULL::date", Value::Null),
    ] {
        let (output, projected) = typed_note_pass(expression).await;
        assert!(
            output.status.success(),
            "a {expression} column must be read: stderr={} stdout={}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            projected,
            vec![json!({"id": "001", "status": null, "note": expected})],
            "{expression} crosses the seam as its canonical value"
        );
    }
}

#[tokio::test]
async fn actual_host_names_the_column_whose_type_it_cannot_read() {
    for expression in ["INTERVAL '1 day'", "ARRAY[1, 2]"] {
        let (output, projected) = typed_note_pass(expression).await;
        assert!(
            !output.status.success(),
            "an unsupported {expression} column must stop the pass"
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
        assert_eq!(
            report["stopped"]["code"],
            "page-fault:adapter.job.postgres-column-type:record:0:column:3",
            "the stop names the third column, never its value"
        );
        assert_eq!(
            report["stopped"]["record"],
            json!({"ordinal": 0, "column": 3})
        );
        assert!(
            projected.is_empty(),
            "an unreadable row reaches no destination"
        );
    }
}

#[tokio::test]
async fn actual_host_refuses_a_null_key_column() {
    let database = DatabaseBinding::from_environment();
    let fixture = Fixture::new(
        &database,
        DestinationKind::SignedCoordinatorEvent,
        SourceQuery::NullKey,
    )
    .await;
    let receiver = FixtureReceiver::start(vec![Scripted::Acknowledge { run_id: None }]).await;
    let output = run_pass(&fixture, &receiver).await;
    assert!(!output.status.success(), "a null key must stop the pass");
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("the stopped pass report is JSON");
    assert_eq!(
        report["stopped"]["code"],
        "page-fault:adapter.job.postgres-key-null:record:0"
    );
    assert!(
        receiver.requests().is_empty(),
        "a keyless row reaches no destination"
    );
}
