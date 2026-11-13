// SPDX-License-Identifier: Apache-2.0

//! The maintained QField/PostGIS example through the actual PostgreSQL source,
//! reviewed mapping, direct BReg destination and durable item store. Every
//! database and login created here has a UUID-derived fixture name.

use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;

use registry_adapter_connectors::breg::{BregConnector, BregConnectorConfig};
use registry_adapter_connectors::operation::Observable;
use registry_adapter_connectors::test_support::field_observer_token;
use registry_adapter_engine::job::compile_job;
use registry_adapter_engine::job_sources::JobRuntimeConfig;
use registry_adapter_job::pass::{run_pass, PassOptions, StopReason};
use registry_adapter_job::postgres_source::activate_postgres_sources;
use registry_adapter_job::runtime_destination::activate_destination;
use registry_adapter_job::store::{self, ItemStatus};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};
use tokio_postgres::{config::Host, Config, NoTls};

use super::postgres_native_source;

const IMMEDIATE_SITE: &str = "10000000-0000-4000-8000-000000000001";
const PROPOSAL_SITE: &str = "10000000-0000-4000-8000-000000000002";
const QFIELD_REGISTRY_FORMAT: registry_platform_yaml::FormatSpec<'static> =
    registry_platform_yaml::FormatSpec {
        kind: "BRegProject",
        envelope: registry_platform_yaml::EnvelopeRule::ApiVersionKind {
            api_versions: &[registry_platform_yaml::ApiVersion::current(
                "id.registrystack.org/formats/breg/project/v1alpha1",
            )],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };

fn field_site_registry(example: &Path) -> Value {
    let path = example.join("registry/registry.yaml");
    registry_platform_yaml::Reader::new(path.display().to_string())
        .decode::<Value>(
            &std::fs::read(&path).expect("read the maintained QField registry"),
            &registry_platform_yaml::Expect::one(&QFIELD_REGISTRY_FORMAT),
        )
        .expect("the maintained QField registry is strict YAML")
        .value
}

struct SourceSite {
    id: &'static str,
    name: &'static str,
    boundary_id: &'static str,
    contacts: [(&'static str, &'static str); 2],
}

const IMMEDIATE: SourceSite = SourceSite {
    id: IMMEDIATE_SITE,
    name: "Clinic Alpha",
    boundary_id: "20000000-0000-4000-8000-000000000001",
    contacts: [
        ("30000000-0000-4000-8000-000000000002", "Second Contact"),
        ("30000000-0000-4000-8000-000000000001", "First Contact"),
    ],
};

const PROPOSAL: SourceSite = SourceSite {
    id: PROPOSAL_SITE,
    name: "Clinic Beta",
    boundary_id: "20000000-0000-4000-8000-000000000002",
    contacts: [
        ("30000000-0000-4000-8000-000000000004", "Fourth Contact"),
        ("30000000-0000-4000-8000-000000000003", "Third Contact"),
    ],
};

struct QfieldSource {
    admin_url: String,
    database_url: String,
    database: String,
    role: String,
    password: String,
    root: tempfile::TempDir,
}

impl QfieldSource {
    async fn start(example: &Path) -> Self {
        let admin_url = std::env::var("ADAPTER_TEST_DATABASE_URL")
            .expect("ADAPTER_TEST_DATABASE_URL names the disposable PostGIS server");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let database = format!("adapter_qfield_source_{suffix}");
        let role = format!("adapter_qfield_reader_{suffix}");
        let password = uuid::Uuid::new_v4().simple().to_string();
        let root = tempfile::tempdir().expect("a QField native fixture directory");
        let mut fixture = Self {
            admin_url: admin_url.clone(),
            database_url: String::new(),
            database,
            role,
            password,
            root,
        };

        let (admin, connection) = tokio_postgres::connect(&admin_url, NoTls)
            .await
            .expect("connect the disposable PostGIS administrator");
        let admin_connection = tokio::spawn(connection);
        admin
            .batch_execute(&format!(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS PASSWORD '{}'",
                fixture.role, fixture.password
            ))
            .await
            .expect("create the fixture-owned source login");
        admin
            .batch_execute(&format!("CREATE DATABASE {}", fixture.database))
            .await
            .expect("create the fixture-owned source database");
        admin_connection.abort();

        let mut database_url = url::Url::parse(&admin_url).expect("the PostGIS URL is valid");
        database_url.set_path(&format!("/{}", fixture.database));
        fixture.database_url = database_url.to_string();
        let (owner, connection) = tokio_postgres::connect(&fixture.database_url, NoTls)
            .await
            .expect("connect the fixture-owned source database");
        let owner_connection = tokio::spawn(connection);
        let schema = std::fs::read_to_string(example.join("source/schema.sql"))
            .expect("read the maintained QField source schema");
        owner
            .batch_execute(&schema)
            .await
            .expect("install the maintained QField source schema");
        let regression = std::fs::read_to_string(example.join("source/test.sql"))
            .expect("read the maintained QField source regression");
        owner
            .batch_execute(&regression)
            .await
            .expect("run the maintained QField source regression");
        owner_connection.abort();

        let (admin, connection) = tokio_postgres::connect(&admin_url, NoTls)
            .await
            .expect("reconnect the disposable PostGIS administrator");
        let admin_connection = tokio::spawn(connection);
        admin
            .batch_execute(&format!(
                "REVOKE CONNECT ON DATABASE {} FROM PUBLIC; GRANT CONNECT ON DATABASE {} TO {}; GRANT field_collection_adapter_reader TO {}",
                fixture.database, fixture.database, fixture.role, fixture.role
            ))
            .await
            .expect("restrict the source database to its projection reader");
        admin_connection.abort();

        fixture.replace_site(&IMMEDIATE).await;
        fixture
    }

    async fn replace_site(&self, site: &SourceSite) {
        let (client, connection) = tokio_postgres::connect(&self.database_url, NoTls)
            .await
            .expect("connect the fixture-owned QField source");
        let connection = tokio::spawn(connection);
        client
            .batch_execute("TRUNCATE field_collection.sites CASCADE")
            .await
            .expect("clear the prior synthetic field submission");
        let mut contact_ids = site.contacts.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        contact_ids.sort_unstable();
        let expected_contacts =
            serde_json::to_string(&contact_ids).expect("the synthetic contact identifiers render");
        client
            .execute(
                "INSERT INTO field_collection.sites \
                 (id, site_name, position, ready, form_version, expected_boundary_id, expected_contact_ids) \
                 VALUES ($1::text::uuid, $2, ST_SetSRID(ST_MakePoint(30, 10), 4326), true, \
                 'field-site-v1', $3::text::uuid, $4)",
                &[&site.id, &site.name, &site.boundary_id, &expected_contacts],
            )
            .await
            .expect("seed the synthetic field-site root");
        client
            .execute(
                "INSERT INTO field_collection.boundaries (id, site_id, boundary) \
                 VALUES ($1::text::uuid, $2::text::uuid, \
                 ST_GeomFromText('POLYGON((29 9,31 9,31 11,29 11,29 9))', 4326))",
                &[&site.boundary_id, &site.id],
            )
            .await
            .expect("seed the synthetic field-site boundary");
        for (id, name) in site.contacts {
            client
                .execute(
                    "INSERT INTO field_collection.contacts (id, site_id, name) \
                     VALUES ($1::text::uuid, $2::text::uuid, $3)",
                    &[&id, &site.id, &name],
                )
                .await
                .expect("seed a synthetic field-site contact");
        }
        connection.abort();
    }

    async fn rename_site(&self, name: &str) {
        let (client, connection) = tokio_postgres::connect(&self.database_url, NoTls)
            .await
            .expect("connect the fixture-owned QField source for its edit");
        let connection = tokio::spawn(connection);
        client
            .execute(
                "UPDATE field_collection.sites SET site_name = $1 WHERE id = $2::text::uuid",
                &[&name, &PROPOSAL_SITE],
            )
            .await
            .expect("revise the synthetic field-site name");
        connection.abort();
    }

    fn runtime(&self, breg_origin: &str, token_endpoint: &str, store_url: &str) -> PathBuf {
        let parsed = Config::from_str(&self.database_url).expect("the source URL parses");
        let host = match parsed.get_hosts().first() {
            Some(Host::Tcp(host)) if host == "localhost" => "127.0.0.1".to_owned(),
            Some(Host::Tcp(host)) => host.clone(),
            _ => panic!("the native QField source uses a TCP host"),
        };
        let port = parsed.get_ports().first().copied().unwrap_or(5432);
        private_file(
            &self.root.path().join("source-password"),
            self.password.as_bytes(),
        );
        private_file(
            &self.root.path().join("breg-private-key"),
            registry_platform_testing::fixtures::ED25519_PRIVATE_JWK.as_bytes(),
        );
        private_file(&self.root.path().join("store-url"), store_url.as_bytes());
        let runtime = json!({
            "apiVersion": "id.registrystack.org/formats/adapter/job-runtime/v1alpha1",
            "kind": "AdapterJobRuntimeConfig",
            "id": "qfield-postgis-native",
            "endpoints": [],
            "sources": {"postgres": {"qfield-sites": {
                "host": host,
                "port": port,
                "database": self.database,
                "user": self.role,
                "passwordRef": "secret:file/source-password",
                "namespace": "qfield-sites-native",
                "tls": {"type": "plaintext"}
            }}},
            "allowedPrivateCidrs": ["127.0.0.0/8"],
            "destinations": {"field-site-registry": {
                "type": "direct-breg",
                "baseUrl": breg_origin,
                "tokenEndpoint": token_endpoint,
                "clientId": "adapter-field-ingestion",
                "privateKeyRef": "secret:file/breg-private-key",
                "scopes": ["registry:write"],
                "resource": "urn:example:applications",
                "attemptTimeoutMilliseconds": 3000
            }},
            "secretProviders": {"file": {"root": self.root.path()}},
            "store": {"runtimeUrlRef": "secret:file/store-url", "testOnlyPlaintext": true}
        });
        let path = self.root.path().join("runtime.yaml");
        private_file(
            &path,
            &serde_json::to_vec_pretty(&runtime).expect("the QField runtime renders"),
        );
        path
    }
}

impl Drop for QfieldSource {
    fn drop(&mut self) {
        let admin_url = self.admin_url.clone();
        let database = self.database.clone();
        let role = self.role.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a source cleanup runtime")
                .block_on(async move {
                    let (admin, connection) = tokio_postgres::connect(&admin_url, NoTls).await?;
                    let connection = tokio::spawn(connection);
                    admin
                        .batch_execute(&format!("DROP DATABASE IF EXISTS {database} WITH (FORCE)"))
                        .await?;
                    admin
                        .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                        .await?;
                    connection.abort();
                    Ok::<(), tokio_postgres::Error>(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("fixture-owned QField source cleanup failed");
        }
    }
}

fn private_file(path: &Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, contents).expect("write a private QField fixture file");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict the QField fixture file");
}

fn example_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/adapter/examples/qfield-postgis")
}

async fn run_example_job(
    example: &Path,
    job: &str,
    runtime_path: &Path,
    source: &QfieldSource,
    pool: &deadpool_postgres::Pool,
    options: PassOptions,
) -> registry_adapter_job::pass::PassReport {
    let mut program = compile_job(&example.join("pack.yaml"), &example.join(job), runtime_path)
        .expect("the maintained QField job compiles");
    let runtime = JobRuntimeConfig::load(runtime_path).expect("the QField runtime loads");
    let resolver = SecretResolver::new([SecretProvider::File], source.root.path())
        .expect("the QField fixture secret resolver starts");
    activate_postgres_sources(&mut program, &resolver)
        .expect("the reviewed PostgreSQL source activates");
    let destination = activate_destination(&program, &runtime, &resolver)
        .await
        .expect("the configured QField BReg destination activates");
    run_pass(pool, &program, destination.as_ref(), options).await
}

async fn migrate_store(pool: &deadpool_postgres::Pool) {
    let client = pool.get().await.expect("the QField item store connects");
    store::migrate(&client)
        .await
        .expect("the QField item store migration applies");
}

async fn only_item_key(pool: &deadpool_postgres::Pool, job: &str) -> String {
    let client = pool.get().await.expect("the QField item store connects");
    client
        .query_one(
            "SELECT item_key FROM adapter_job_items WHERE job_id = $1",
            &[&job],
        )
        .await
        .expect("read the QField item key")
        .get(0)
}

async fn field_site(
    service: &registry_adapter_connectors::test_support::Breg,
    issuer: &registry_platform_testing::TestAuthorizationServer,
    id: &str,
) -> Value {
    service.field_site(issuer, id).await
}

fn assert_site(value: &Value, site: &SourceSite) {
    assert_eq!(value["owner"], "adapter-field-ingestion");
    assert_eq!(value["sourceSubmissionId"], site.id);
    assert_eq!(value["siteName"], site.name);
    assert_eq!(
        value["position"],
        json!({"type": "Point", "coordinates": [30, 10]})
    );
    assert_eq!(
        value["boundary"],
        json!({
            "type": "Polygon",
            "coordinates": [[[29, 11], [31, 11], [31, 9], [29, 9], [29, 11]]]
        })
    );
    let mut contacts = site
        .contacts
        .iter()
        .map(|(id, name)| json!({"id": id, "name": name}))
        .collect::<Vec<_>>();
    contacts.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    assert_eq!(value["contacts"], Value::Array(contacts));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "runs under the Adapter native connector runner"]
async fn qfield_postgis_reaches_both_native_breg_action_modes_without_payload_storage() {
    let issuer = registry_adapter_connectors::test_support::issuer("adapter-job-native").await;
    let example = example_root();
    let service = registry_adapter_connectors::test_support::Breg::start_with_field_site(
        &issuer,
        field_site_registry(&example),
    )
    .await;
    let source = QfieldSource::start(&example).await;

    // The subject and scope match the allowed caller. Only the authenticated
    // requester client differs. Exercise both mutation routes directly.
    let unapproved = issuer.issue_access_token(
        "application-reader",
        "adapter-field-ingestion",
        "urn:example:applications",
        "registry:write",
        chrono::Utc::now().timestamp() + 3600,
    );
    let http = reqwest::Client::new();
    let observer = field_observer_token(
        &issuer,
        "field-intake-reconciliation",
        "adapter-field-ingestion",
    );
    for (token, profile) in [(&unapproved, "ingestion"), (&observer, "reconciliation")] {
        for route in ["register-site", "propose-site/proposals"] {
            let denied = http
                .post(format!(
                    "{}/v1/actions/{route}?accessProfile={profile}",
                    service.origin()
                ))
                .bearer_auth(token)
                .header("idempotency-key", "qfield-unapproved-requester")
                .json(&json!({"input": {
                    "sourceSubmissionId": IMMEDIATE_SITE,
                    "siteName": IMMEDIATE.name,
                    "position": {"type": "Point", "coordinates": [30, 10]},
                    "boundary": {"type": "Polygon", "coordinates": [[[29, 9], [31, 9], [31, 11], [29, 11], [29, 9]]]},
                    "contacts": IMMEDIATE.contacts.map(|(id, name)| json!({"id": id, "name": name}))
                }}))
                .send()
                .await
                .expect("the unauthorized mutation receives an answer");
            assert_eq!(denied.status(), reqwest::StatusCode::NOT_FOUND);
        }
    }

    let immediate_store = super::isolated_store_binding().await;
    let runtime = source.runtime(
        &service.origin(),
        &issuer.token_endpoint(),
        &immediate_store.url,
    );
    migrate_store(&immediate_store.pool).await;
    let first = run_example_job(
        &example,
        "job.yaml",
        &runtime,
        &source,
        &immediate_store.pool,
        PassOptions::default(),
    )
    .await;
    assert_eq!(first.stopped, None);
    assert_eq!(first.items_new, 1);
    assert_eq!(first.items_acknowledged, 1);
    assert_site(
        &field_site(&service, &issuer, IMMEDIATE_SITE).await,
        &IMMEDIATE,
    );

    let lookup_url = format!(
        "{}/v1/records/field-sites:lookup?accessProfile=reconciliation",
        service.origin()
    );
    let lookup_body = json!({
        "selector": "by-source-submission",
        "values": {"sourceSubmissionId": IMMEDIATE_SITE}
    });
    let now = chrono::Utc::now().timestamp();
    let readback = http
        .post(&lookup_url)
        .bearer_auth(&observer)
        .json(&lookup_body)
        .send()
        .await
        .expect("the observer's record lookup answers");
    assert_eq!(readback.status(), reqwest::StatusCode::OK);
    let record: Value = readback
        .json()
        .await
        .expect("the readback uses the Record envelope");
    assert_eq!(
        record["data"]["domainData"]["sourceSubmissionId"],
        IMMEDIATE_SITE
    );
    let wrong_owner =
        field_observer_token(&issuer, "field-intake-reconciliation", "another-collection");
    let wrong_purpose = field_observer_token(&issuer, "another-purpose", "adapter-field-ingestion");
    let ingestion = issuer.issue_access_token_with_claims(
        "adapter-field-ingestion",
        "adapter-field-ingestion",
        "urn:example:applications",
        "registry:write registry:reconcile",
        now + 3600,
        [
            (
                "registry_purpose".to_owned(),
                json!("field-intake-reconciliation"),
            ),
            (
                "field_collection_owner".to_owned(),
                json!("adapter-field-ingestion"),
            ),
        ]
        .into(),
    );
    for token in [&ingestion, &wrong_owner, &wrong_purpose] {
        let denied = http
            .post(&lookup_url)
            .bearer_auth(token)
            .json(&lookup_body)
            .send()
            .await
            .expect("the unauthorized lookup receives an answer");
        assert_eq!(denied.status(), reqwest::StatusCode::NOT_FOUND);
    }
    let records_url = format!("{}/v1/records/field-sites", service.origin());
    let record_id = record["data"]["recordIdentifier"]
        .as_str()
        .expect("the lookup returns the record identifier");
    for (url, token) in [
        (
            format!("{records_url}?accessProfile=reconciliation"),
            &observer,
        ),
        (
            format!("{records_url}/{record_id}?accessProfile=reconciliation"),
            &observer,
        ),
        (
            format!("{records_url}/{record_id}?accessProfile=ingestion"),
            &ingestion,
        ),
    ] {
        let denied = http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .expect("the ungranted read receives an answer");
        assert_eq!(denied.status(), reqwest::StatusCode::NOT_FOUND);
    }
    let denied = http
        .post(format!("{}/v1/records/field-sites?accessProfile=reconciliation", service.origin()))
        .bearer_auth(&observer)
        .header("idempotency-key", "qfield-observer-direct-write")
        .json(&json!({"data": {
            "owner": "adapter-field-ingestion",
            "sourceSubmissionId": PROPOSAL_SITE,
            "siteName": PROPOSAL.name,
            "position": {"type": "Point", "coordinates": [30, 10]},
            "boundary": {"type": "Polygon", "coordinates": [[[29, 9], [31, 9], [31, 11], [29, 11], [29, 9]]]},
            "contacts": PROPOSAL.contacts.map(|(id, name)| json!({"id": id, "name": name}))
        }}))
        .send().await.expect("the observer direct write attempt receives an answer");
    assert_eq!(denied.status(), reqwest::StatusCode::NOT_FOUND);

    let repeated = run_example_job(
        &example,
        "job.yaml",
        &runtime,
        &source,
        &immediate_store.pool,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(repeated.stopped, None);
    assert_eq!(repeated.items_skipped, 1);
    postgres_native_source::assert_no_payload_columns(&immediate_store.pool).await;

    source.replace_site(&PROPOSAL).await;
    let proxy = super::LostSubmitProxy::start(service.origin()).await;
    let proposal_store = super::isolated_store_binding().await;
    let runtime = source.runtime(&proxy.origin, &issuer.token_endpoint(), &proposal_store.url);
    migrate_store(&proposal_store.pool).await;
    let lost = run_example_job(
        &example,
        "job.proposal.yaml",
        &runtime,
        &source,
        &proposal_store.pool,
        PassOptions::default(),
    )
    .await;
    assert_eq!(
        lost.stopped,
        Some(StopReason::DestinationStop {
            code: "adapter.job.breg-outcome-uncertain".to_owned()
        })
    );
    assert_eq!(lost.items_new, 1);
    let proposal_item_key = only_item_key(&proposal_store.pool, "qfield-sites-proposal").await;
    let client = proposal_store
        .pool
        .get()
        .await
        .expect("the proposal store connects");
    let pending = store::inspect_item(&client, "qfield-sites-proposal", &proposal_item_key)
        .await
        .expect("read the uncertain QField Proposal item")
        .expect("the uncertain QField Proposal item exists");
    assert_eq!(pending.status, ItemStatus::Pending);
    assert_eq!(pending.sequence, 1);
    assert!(pending.run_id.is_none());
    drop(client);
    let original_proposal = proxy.proposal_id();
    let original_start_keys = proxy.start_command_keys();
    let original_submit_keys = proxy.submit_command_keys();
    assert!(!original_start_keys.is_empty());
    assert!(!original_submit_keys.is_empty());
    proxy.allow_answers();
    let proposed = run_example_job(
        &example,
        "job.proposal.yaml",
        &runtime,
        &source,
        &proposal_store.pool,
        PassOptions::default(),
    )
    .await;
    assert_eq!(proposed.stopped, None);
    assert_eq!(proposed.items_redelivered, 1);
    assert_eq!(proposed.items_acknowledged, 1);
    assert_site(
        &field_site(&service, &issuer, PROPOSAL_SITE).await,
        &PROPOSAL,
    );
    let client = proposal_store
        .pool
        .get()
        .await
        .expect("the proposal item store connects");
    let proposal_item = store::inspect_item(&client, "qfield-sites-proposal", &proposal_item_key)
        .await
        .expect("read the admitted QField proposal item")
        .expect("the admitted QField proposal item exists");
    let proposal = proposal_item
        .run_id
        .expect("the QField destination retained its Proposal reference");
    assert_eq!(proposal_item.status, ItemStatus::Acknowledged);
    assert_eq!(proposal_item.sequence, 1);
    assert_eq!(proposal, original_proposal);
    assert!(proxy.started_proposals().iter().all(|id| id == &proposal));
    assert!(proxy
        .start_command_keys()
        .iter()
        .all(|key| key == &original_start_keys[0]));
    assert!(proxy
        .submit_command_keys()
        .iter()
        .all(|key| key == &original_submit_keys[0]));
    drop(client);
    let proposal_connector = Arc::new(
        BregConnector::connect(BregConnectorConfig::for_action(
            service.origin(),
            registry_adapter_connectors::test_support::field_ingestion_token_provider(&issuer),
            "ingestion",
            "propose-site",
        ))
        .await
        .expect("the QField Proposal observer connects"),
    );
    let proposal_state = proposal_connector
        .proposal_submit()
        .observe(&proposal)
        .expect("the original QField Proposal remains observable");
    assert_eq!(proposal_state.state, "applied");

    source.rename_site("Clinic Beta revised").await;
    let revised = run_example_job(
        &example,
        "job.proposal.yaml",
        &runtime,
        &source,
        &proposal_store.pool,
        PassOptions {
            rescan: true,
            ..PassOptions::default()
        },
    )
    .await;
    assert_eq!(revised.stopped, None);
    assert_eq!(revised.items_changed, 1);
    assert_eq!(revised.items_held, 1);
    assert_eq!(
        revised.holds_by_code.get("adapter.job.revised-item"),
        Some(&1)
    );
    assert_eq!(
        field_site(&service, &issuer, PROPOSAL_SITE).await["siteName"],
        PROPOSAL.name,
        "a later source edit cannot mutate the admitted create-only Record"
    );
    let client = proposal_store
        .pool
        .get()
        .await
        .expect("the proposal item store connects");
    let item = store::inspect_item(&client, "qfield-sites-proposal", &proposal_item_key)
        .await
        .expect("read the QField proposal item")
        .expect("the QField proposal item exists");
    assert_eq!(item.status, ItemStatus::Held);
    assert_eq!(item.sequence, 2);
    assert_eq!(item.run_id.as_deref(), Some(proposal.as_str()));
    drop(client);
    postgres_native_source::assert_no_payload_columns(&proposal_store.pool).await;
    service.finish();
}
