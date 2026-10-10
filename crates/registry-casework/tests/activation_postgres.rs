//! Package activation against real PostgreSQL: the ledger, the one apply
//! transaction, the migration lock, role separation, and the read-only
//! startup check. Each test owns a schema in the database named by
//! `CASEWORK_ACTIVATION_TEST_DATABASE_URL`, and the split-role tests create
//! and drop their own login roles.

use std::env;
use std::time::Duration;

use async_trait::async_trait;
use registry_casework::{
    check_activation, check_pinned_work, ActivationCandidate, ActivationError, ApplyRequest,
    AuditCapture, CaseworkAudit, DatabaseConfig, DatabaseIdCheck, GenerationChange, PlanKind,
    PostgresStore, RoleMode, RuntimeError, StoreError, TemplateChange, MIGRATION_LOCK_KEY,
};
use registry_casework_core::{
    ActiveSubjectsPage, AuthoritativeObservation, CallerSubjectView, CaseworkProject,
    DiscoveryCursor, EphemeralCredential, EventRequest, ExecutePreparedRequest,
    PrepareActionRequest, PreparedSourceAttempt, SourceAdapter, SourceAdapterError, SourceReceipt,
    SubjectRef, TaskTemplate, TransitionHint,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const DATABASE_ID: &str = "casework-activation-test";

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn base_url() -> String {
    env::var("CASEWORK_ACTIVATION_TEST_DATABASE_URL")
        .expect("CASEWORK_ACTIVATION_TEST_DATABASE_URL must name a disposable database")
}

fn scoped(url: &str, schema: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-csearch_path%3D{schema}")
}

/// `url` with its user and password replaced.
fn with_login(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("database URL has a scheme");
    let (_, host) = rest.split_once('@').expect("database URL names a user");
    format!("{scheme}://{user}:{password}@{host}")
}

async fn connect(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect the activation test database");
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            panic!("activation test connection failed: {error}");
        }
    });
    client
}

fn secret_ref(url: &str) -> String {
    let name = format!("CASEWORK_ACTIVATION_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&name, url);
    format!("secret:env/{name}")
}

fn secrets() -> SecretResolver {
    SecretResolver::new([SecretProvider::Environment], "/private/tmp").expect("test resolver")
}

struct Fixture {
    /// Connected with the migration credential and a capturing audit.
    migration: PostgresStore,
    capture: AuditCapture,
    /// A direct connection into the schema as the migration role.
    client: Client,
    schema: String,
    database: DatabaseConfig,
    /// The role the runtime credential connects as.
    runtime_user: String,
    runtime_url: String,
}

impl Fixture {
    /// One isolated schema whose runtime and migration credentials are the
    /// same role.
    async fn single(prefix: &str) -> Self {
        let base = base_url();
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
        connect(&base)
            .await
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .expect("create isolated schema");
        let url = scoped(&base, &schema);
        let reference = secret_ref(&url);
        let database = DatabaseConfig {
            runtime_url_ref: reference.clone(),
            migration_url_ref: reference,
            trusted_root_certificate_ref: None,
            test_only_plaintext: true,
        };
        Self::open(database, &url, url.clone(), schema).await
    }

    /// One isolated schema whose runtime credential is a separate login
    /// role with no privilege of its own.
    async fn split(prefix: &str) -> Self {
        let base = base_url();
        let schema = format!("{prefix}_{}", Uuid::new_v4().simple());
        let role = format!("cw_runtime_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        connect(&base)
            .await
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
            ))
            .await
            .expect("create isolated schema and runtime role");
        let url = scoped(&base, &schema);
        let runtime_url = scoped(&with_login(&base, &role, &password), &schema);
        let database = DatabaseConfig {
            runtime_url_ref: secret_ref(&runtime_url),
            migration_url_ref: secret_ref(&url),
            trusted_root_certificate_ref: None,
            test_only_plaintext: true,
        };
        Self::open(database, &url, runtime_url, schema).await
    }

    async fn open(
        database: DatabaseConfig,
        url: &str,
        runtime_url: String,
        schema: String,
    ) -> Self {
        let (audit, capture) = CaseworkAudit::capture();
        let migration = PostgresStore::connect_migration(&database, &secrets())
            .expect("migration pool")
            .with_audit(audit);
        let runtime_user = PostgresStore::connect_runtime(&database, &secrets())
            .expect("runtime pool")
            .current_user()
            .await
            .expect("read the runtime role");
        Self {
            migration,
            capture,
            client: connect(url).await,
            schema,
            database,
            runtime_user,
            runtime_url,
        }
    }

    fn runtime(&self) -> PostgresStore {
        PostgresStore::connect_runtime(&self.database, &secrets())
            .expect("runtime pool")
            .with_audit(CaseworkAudit::capture().0)
    }

    async fn apply(
        &self,
        candidate: &ActivationCandidate<'_>,
    ) -> Result<registry_casework::ActivationApplied, ActivationError> {
        self.migration
            .apply_activation(&self.runtime_user, candidate, &ApplyRequest::default())
            .await
    }

    async fn ledger(&self) -> Vec<(i64, String, Option<String>, String)> {
        let exists: bool = self
            .client
            .query_one(
                "SELECT to_regclass('casework_activations') IS NOT NULL",
                &[],
            )
            .await
            .expect("read the catalogue")
            .get(0);
        if !exists {
            return Vec::new();
        }
        self.client
            .query(
                "SELECT apply_order,package_digest,predecessor_package_digest,plan_kind FROM casework_activations ORDER BY apply_order",
                &[],
            )
            .await
            .expect("read the ledger")
            .into_iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
            .collect()
    }

    async fn relation_count(&self) -> i64 {
        self.client
            .query_one(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1",
                &[&self.schema],
            )
            .await
            .expect("count relations")
            .get(0)
    }

    async fn active_templates(&self) -> Vec<(String, String)> {
        self.client
            .query(
                "SELECT template_id,template_version FROM casework_task_templates WHERE active ORDER BY 1,2",
                &[],
            )
            .await
            .expect("read task templates")
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    /// A separate login role with no privilege of its own, and a runtime
    /// store connected as it.
    async fn login_role(&self) -> (String, PostgresStore) {
        let role = format!("cw_runtime_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        self.client
            .batch_execute(&format!(
                "CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
            ))
            .await
            .expect("create a runtime role");
        let url = scoped(&with_login(&base_url(), &role, &password), &self.schema);
        let database = DatabaseConfig {
            runtime_url_ref: secret_ref(&url),
            ..self.database.clone()
        };
        let store = PostgresStore::connect_runtime(&database, &secrets())
            .expect("runtime pool")
            .with_audit(CaseworkAudit::capture().0);
        (role, store)
    }

    /// Drop the schema, then every role in `roles`.
    async fn drop_roles(&self, roles: &[&str]) {
        self.client
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .expect("drop the schema");
        for role in roles {
            self.client
                .batch_execute(&format!("DROP OWNED BY {role}; DROP ROLE {role}"))
                .await
                .expect("drop a runtime role");
        }
    }

    async fn apply_as(
        &self,
        runtime_user: &str,
        candidate: &ActivationCandidate<'_>,
    ) -> Result<registry_casework::ActivationApplied, ActivationError> {
        self.migration
            .apply_activation(runtime_user, candidate, &ApplyRequest::default())
            .await
    }

    async fn drop_runtime_role(&self) {
        if self.runtime_user == self.migration.current_user().await.expect("migration role") {
            return;
        }
        self.client
            .batch_execute(&format!(
                "DROP SCHEMA {schema} CASCADE; DROP OWNED BY {role}; DROP ROLE {role}",
                schema = self.schema,
                role = self.runtime_user
            ))
            .await
            .expect("drop the runtime role");
    }
}

fn project() -> CaseworkProject {
    CaseworkProject::load(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../products/casework/examples/standalone-decision/casework.yaml"
    ))
    .expect("load the standalone example project")
}

fn template(id: &str, version: &str, purpose: &str) -> TaskTemplate {
    serde_json::from_value(json!({
        "id": id, "version": version, "label": "Prepare summary",
        "eligibleTeams": ["team"], "eligibleProfiles": ["staff"], "source": "source",
        "itemKinds": ["request"], "itemStates": ["claimed"],
        "agent": {"issuer": "https://issuer.test", "subject": "agent"},
        "client": "agent-client", "resource": "urn:breg:test", "purpose": purpose,
        "scopes": ["records:get"],
        "bounds": {"type": "breg", "permissions": [{"collection": "people", "operations": ["get"]}]},
        "subjects": {"person_reference": "person-reference"},
        "lifetimeSeconds": 300
    }))
    .expect("task template fixture")
}

struct FakeSource {
    id: String,
    generation: String,
}

impl FakeSource {
    fn new(id: &str, generation: &str) -> Self {
        Self {
            id: id.to_owned(),
            generation: generation.to_owned(),
        }
    }
}

#[async_trait]
impl SourceAdapter for FakeSource {
    fn source_id(&self) -> &str {
        &self.id
    }

    fn binding_generation(&self) -> &str {
        &self.generation
    }

    async fn verify_transition(
        &self,
        _request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }

    async fn read_authoritative(
        &self,
        _subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }

    async fn read_for_caller(
        &self,
        _subject: &SubjectRef,
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }

    async fn prepare_action(
        &self,
        _request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }

    async fn execute_prepared(
        &self,
        _request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Denied)
    }
}

fn candidate<'a>(
    project: &'a CaseworkProject,
    digest: &'a str,
    adapters: &'a [&'a dyn SourceAdapter],
) -> ActivationCandidate<'a> {
    ActivationCandidate {
        database_id: DATABASE_ID,
        package_digest: digest,
        acknowledged_stranded_work: None,
        project,
        adapters,
    }
}

fn refusal_codes(error: &ActivationError) -> Vec<String> {
    match error {
        ActivationError::Refused(refusals) => refusals
            .iter()
            .map(|refusal| refusal.code.clone())
            .collect(),
        other => panic!("expected a refusal, got {other}"),
    }
}

fn activation_responses(capture: &AuditCapture) -> Vec<serde_json::Value> {
    capture
        .entries()
        .into_iter()
        .filter(|entry| {
            entry["phase"] == "response" && entry["schema"] == "casework-activation-audit/v1"
        })
        .collect()
}

#[tokio::test]
async fn plan_against_an_empty_database_writes_nothing() {
    let fixture = Fixture::single("plan_empty").await;
    let project = project();
    let first = digest('a');
    let plan = fixture
        .migration
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan an empty database");
    assert!(plan.active.is_none());
    assert_eq!(plan.database_id_check, DatabaseIdCheck::NotRecorded);
    assert_eq!(plan.plan_kind, PlanKind::Initial);
    assert_eq!(plan.schema_version, None);
    assert_eq!(plan.pending_schema_versions.len(), 21);
    assert!(plan.changes_pending, "{:?}", plan.refusals);
    assert_eq!(
        fixture.relation_count().await,
        0,
        "a plan creates no relation"
    );
    assert!(
        fixture.capture.entries().is_empty(),
        "a plan writes no audit entry"
    );
}

#[tokio::test]
async fn initial_apply_records_the_package_and_a_previous_package_reapplies_as_a_new_row() {
    let fixture = Fixture::single("reapply").await;
    let project = project();
    let (first, second) = (digest('a'), digest('b'));
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("initial apply");
    assert_eq!(applied.activation.plan_kind, PlanKind::Initial);
    assert_eq!(applied.activation.role_mode, RoleMode::Single);
    assert_eq!(
        applied.schema_versions_applied,
        (1..=21).collect::<Vec<_>>()
    );
    fixture
        .apply(&candidate(&project, &second, &[]))
        .await
        .expect("successor apply");
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("the previous package applies again");
    assert_eq!(
        fixture.ledger().await,
        vec![
            (1, first.clone(), None, "initial".to_owned()),
            (
                2,
                second.clone(),
                Some(first.clone()),
                "successor".to_owned()
            ),
            (3, first.clone(), Some(second), "successor".to_owned()),
        ]
    );
    let status = fixture.runtime().activation_status().await.expect("status");
    assert_eq!(status.history.len(), 3);
    assert_eq!(status.active.expect("active").package_digest, first);
    assert_eq!(status.role_mode, Some(RoleMode::Single));
    let responses = activation_responses(&fixture.capture);
    assert_eq!(responses.len(), 3, "one response per activation");
    assert!(responses
        .iter()
        .all(|entry| entry["record"]["outcome"] == "applied"));
}

#[tokio::test]
async fn reapplying_the_active_package_is_refused_and_writes_nothing() {
    let fixture = Fixture::single("same").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("initial apply");
    let error = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect_err("the active package is refused");
    assert_eq!(
        refusal_codes(&error),
        ["casework.activation.already-active"]
    );
    assert!(error.to_string().contains(&first));
    assert!(error.to_string().contains("nothing needs applying"));
    assert_eq!(fixture.ledger().await.len(), 1);
    let responses = activation_responses(&fixture.capture);
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1]["record"]["outcome"], "refused");
    let plan = fixture
        .migration
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan");
    assert!(!plan.changes_pending);
}

#[tokio::test]
async fn a_changed_source_binding_reapplies_the_same_package() {
    let fixture = Fixture::single("rebind").await;
    let project = project();
    let first = digest('a');
    let one = FakeSource::new("source", "generation-1");
    fixture
        .apply(&candidate(&project, &first, &[&one]))
        .await
        .expect("initial apply");
    let two = FakeSource::new("source", "generation-2");
    let plan = fixture
        .migration
        .plan_activation(&candidate(&project, &first, &[&two]))
        .await
        .expect("plan the rebinding");
    assert!(plan.changes_pending);
    assert_eq!(
        plan.effects.expect("effects").source_generations[0].change,
        GenerationChange::Changed
    );
    fixture
        .apply(&candidate(&project, &first, &[&two]))
        .await
        .expect("a rebinding applies the same package");
    let runtime = fixture.runtime();
    let current = FakeSource::new("source", "generation-2");
    check_activation(&runtime, DATABASE_ID, &first, &[&current])
        .await
        .expect("the recorded generation starts");
    let stale = FakeSource::new("source", "generation-1");
    assert!(matches!(
        check_activation(&runtime, DATABASE_ID, &first, &[&stale]).await,
        Err(RuntimeError::SourceGenerationNotActive(source)) if source == "source"
    ));
}

#[tokio::test]
async fn a_database_id_mismatch_is_refused_before_any_change() {
    let fixture = Fixture::single("dbid").await;
    let mut project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("initial apply");
    project
        .task_templates
        .push(template("summary", "1", "prepare-summary"));
    let second = digest('b');
    let mut other = candidate(&project, &second, &[]);
    other.database_id = "another-database";
    let plan = fixture
        .migration
        .plan_activation(&other)
        .await
        .expect("plan");
    assert_eq!(plan.database_id_check, DatabaseIdCheck::Differs);
    assert!(!plan.changes_pending);
    let error = fixture
        .apply(&other)
        .await
        .expect_err("another database's configuration is refused");
    assert_eq!(
        refusal_codes(&error),
        ["casework.activation.database-id-mismatch"]
    );
    let message = error.to_string();
    assert!(message.contains(
        "the package deployment binding differs from the runtime configuration at identity.databaseId"
    ));
    // Apply connects with the migration credential, so the recovery names
    // both credentials a wrong database can come from.
    assert!(
        message.contains("database.runtimeUrlRef and database.migrationUrlRef"),
        "{message}"
    );
    assert!(!message.contains("another-database") && !message.contains(DATABASE_ID));
    assert_eq!(fixture.ledger().await.len(), 1);
    assert!(
        fixture.active_templates().await.is_empty(),
        "the refused apply activated no template"
    );
}

#[tokio::test]
async fn templates_are_activated_and_retired_by_apply_only() {
    let fixture = Fixture::single("templates").await;
    let mut project = project();
    project
        .task_templates
        .push(template("summary", "1", "prepare-summary"));
    let first = digest('a');
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("initial apply");
    assert_eq!(
        applied.effects.task_templates[0].change,
        TemplateChange::Added
    );
    assert_eq!(
        fixture.active_templates().await,
        [("summary".to_owned(), "1".to_owned())]
    );
    project.task_templates = vec![template("summary", "2", "prepare-summary")];
    let second = digest('b');
    let plan = fixture
        .migration
        .plan_activation(&candidate(&project, &second, &[]))
        .await
        .expect("plan");
    let changes: Vec<_> = plan
        .effects
        .expect("effects")
        .task_templates
        .into_iter()
        .map(|effect| (effect.template_version, effect.change))
        .collect();
    assert_eq!(
        changes,
        [
            ("2".to_owned(), TemplateChange::Added),
            ("1".to_owned(), TemplateChange::Deactivated)
        ]
    );
    assert_eq!(
        fixture.active_templates().await,
        [("summary".to_owned(), "1".to_owned())],
        "a plan changes no template"
    );
    fixture
        .apply(&candidate(&project, &second, &[]))
        .await
        .expect("successor apply");
    assert_eq!(
        fixture.active_templates().await,
        [("summary".to_owned(), "2".to_owned())]
    );
    project.task_templates = vec![template("summary", "2", "a-changed-purpose")];
    let error = fixture
        .apply(&candidate(&project, &digest('c'), &[]))
        .await
        .expect_err("a changed stored template is refused");
    assert_eq!(
        refusal_codes(&error),
        ["casework.activation.template-changed"]
    );
    assert_eq!(fixture.ledger().await.len(), 2);
}

#[tokio::test]
async fn a_refused_audit_request_leaves_the_database_untouched() {
    let fixture = Fixture::single("audit").await;
    fixture.capture.refuse_after(0);
    let project = project();
    let error = fixture
        .apply(&candidate(&project, &digest('a'), &[]))
        .await
        .expect_err("apply without an accepted audit request");
    assert!(
        matches!(error, ActivationError::Store(StoreError::AuditUnavailable)),
        "{error}"
    );
    assert_eq!(
        fixture.relation_count().await,
        0,
        "no migration ran without an accepted audit request"
    );
    assert!(
        fixture.capture.entries().is_empty(),
        "the destination accepted no entry"
    );
}

#[tokio::test]
async fn a_refused_audit_response_after_commit_reports_the_activation_applied_but_unaudited() {
    let fixture = Fixture::single("unaudited").await;
    // The request entry is accepted; the response entry after the commit is
    // refused.
    fixture.capture.refuse_after(1);
    let project = project();
    let first = digest('a');
    let error = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect_err("the response entry is refused");
    let ActivationError::AppliedUnaudited {
        activation_id,
        package_digest,
    } = &error
    else {
        panic!("expected an applied but unaudited activation, got {error}");
    };
    assert_eq!(package_digest, &first);
    let message = error.to_string();
    assert!(message.contains(&first) && message.contains(&activation_id.to_string()));
    assert!(message.contains("caseworkctl status"), "{message}");
    assert_eq!(fixture.ledger().await.len(), 1, "the activation committed");
    check_activation(&fixture.runtime(), DATABASE_ID, &first, &[])
        .await
        .expect("the applied package starts");
}

#[tokio::test]
async fn the_same_operator_reference_in_two_activations_is_stored_under_different_hashes() {
    let fixture = Fixture::single("opref").await;
    let project = project();
    let reference = "change-4711";
    for fill in ['a', 'b'] {
        fixture
            .migration
            .apply_activation(
                &fixture.runtime_user,
                &candidate(&project, &digest(fill), &[]),
                &ApplyRequest {
                    operator_reference: Some(reference.to_owned()),
                    backup_references: Vec::new(),
                },
            )
            .await
            .expect("apply with an operator reference");
    }
    let hashes: Vec<Option<String>> = fixture
        .client
        .query(
            "SELECT operator_reference_hash FROM casework_activations ORDER BY apply_order",
            &[],
        )
        .await
        .expect("read the ledger")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let [Some(first), Some(second)] = hashes.as_slice() else {
        panic!("both activations record a hash: {hashes:?}");
    };
    assert_ne!(first, second, "each hash is scoped by its activation id");
    assert!(!first.contains(reference) && !second.contains(reference));
    let entries = serde_json::to_string(&fixture.capture.entries()).expect("entries");
    assert!(
        !entries.contains(reference),
        "the audit never carries the raw reference"
    );
}

#[tokio::test]
async fn a_concurrent_apply_waits_for_the_migration_lock() {
    let fixture = Fixture::single("lock").await;
    let project = project();
    let first = digest('a');
    let mut holder = connect(&scoped(&base_url(), &fixture.schema)).await;
    let lock = holder.transaction().await.expect("begin the lock holder");
    lock.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .expect("take the migration lock");
    let blocked = tokio::time::timeout(
        Duration::from_millis(750),
        fixture.apply(&candidate(&project, &first, &[])),
    )
    .await;
    assert!(blocked.is_err(), "apply waited for the migration lock");
    assert!(
        fixture.ledger().await.is_empty(),
        "nothing was recorded while the lock was held"
    );
    lock.commit().await.expect("release the migration lock");
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply after the lock is released");
    assert_eq!(fixture.ledger().await.len(), 1);
}

#[tokio::test]
async fn startup_refuses_an_unapplied_database_another_package_and_another_database() {
    let fixture = Fixture::single("startup").await;
    let project = project();
    let first = digest('a');
    fixture
        .migration
        .migrate()
        .await
        .expect("migrate without activating");
    let runtime = fixture.runtime();
    let unapplied = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a database with no activation is refused");
    assert!(matches!(unapplied, RuntimeError::NotActivated));
    assert!(unapplied
        .to_string()
        .contains("caseworkctl plan --runtime-config FILE"));
    assert!(unapplied
        .to_string()
        .contains("caseworkctl apply --runtime-config FILE"));

    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply");
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("the active package starts"),
        RoleMode::Single
    );
    let second = digest('b');
    let other_package = check_activation(&runtime, DATABASE_ID, &second, &[])
        .await
        .expect_err("another package is refused");
    let message = other_package.to_string();
    assert!(matches!(
        other_package,
        RuntimeError::PackageNotActive { .. }
    ));
    assert!(
        message.contains(&first) && message.contains(&second),
        "{message}"
    );
    assert!(message.contains("caseworkctl apply --runtime-config FILE"));
    let other_database = check_activation(&runtime, "another-database", &first, &[])
        .await
        .expect_err("another database's configuration is refused");
    assert!(matches!(other_database, RuntimeError::DatabaseIdMismatch));
    assert!(!other_database.to_string().contains("another-database"));
}

#[tokio::test]
async fn split_role_runtime_cannot_write_the_ledgers_but_still_serves() {
    let fixture = Fixture::split("split").await;
    let project = project();
    let first = digest('a');
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    let runtime = fixture.runtime();
    runtime
        .ready()
        .await
        .expect("the runtime role reads the schema");
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("the runtime role starts"),
        RoleMode::Split
    );
    let client = connect(&fixture.runtime_url).await;
    for statement in [
        "INSERT INTO casework_activations(activation_id,apply_order,package_digest,database_id,plan_kind,role_mode) VALUES(gen_random_uuid(),99,'sha256:0000000000000000000000000000000000000000000000000000000000000000','x','initial','single')",
        "UPDATE casework_activations SET database_id='x'",
        "DELETE FROM casework_activations",
        "TRUNCATE casework_activations",
        "INSERT INTO casework_schema_migrations(version) VALUES(999)",
        "DELETE FROM casework_schema_migrations",
    ] {
        let error = client
            .batch_execute(statement)
            .await
            .expect_err("the runtime role cannot write a ledger");
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
    }
    client
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('team',1); UPDATE casework_teams SET revision=2; DELETE FROM casework_teams",
        )
        .await
        .expect("the runtime role writes service state");
    let service =
        registry_casework::CaseworkService::new(runtime.clone(), project.clone(), Vec::new())
            .expect("service");
    service
        .synchronize_pending(10)
        .await
        .expect("the runtime role runs a synchronization pass");
    service
        .process_due_clocks(10)
        .await
        .expect("the runtime role runs a clock pass");
    drop(client);
    fixture
        .apply(&candidate(&project, &digest('b'), &[]))
        .await
        .expect("a second split-role apply reissues the grants");
    assert_eq!(
        runtime.effective_role_mode().await.expect("role mode"),
        Some(RoleMode::Split)
    );
    drop(runtime);
    fixture.drop_runtime_role().await;
}

#[tokio::test]
async fn single_role_status_reports_what_the_ledger_cannot_catch() {
    let fixture = Fixture::single("single").await;
    let project = project();
    fixture
        .apply(&candidate(&project, &digest('a'), &[]))
        .await
        .expect("apply");
    let status = fixture.runtime().activation_status().await.expect("status");
    assert_eq!(status.role_mode, Some(RoleMode::Single));
    assert!(
        registry_casework::SINGLE_ROLE_STATEMENT.contains("not someone holding this credential")
    );
}

#[tokio::test]
async fn stranded_work_is_refused_until_the_exact_package_is_acknowledged() {
    let fixture = Fixture::single("stranded").await;
    let project = project();
    fixture
        .apply(&candidate(&project, &digest('a'), &[]))
        .await
        .expect("initial apply");
    // Open work from a source no adapter binds any more.
    fixture
        .client
        .execute(
            "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,revision,first_observed_at,updated_at) VALUES($1,'retired-source','request','subject-1','review','review-1',$2,'open','retired-queue',1,now(),now())",
            &[
                &Uuid::new_v4(),
                &json!({"sourceRevision": "1", "version": "proposal-1", "generation": "retired"}),
            ],
        )
        .await
        .expect("seed pinned work");
    let second = digest('b');
    let plan = fixture
        .migration
        .plan_activation(&candidate(&project, &second, &[]))
        .await
        .expect("plan");
    assert_eq!(
        plan.effects.expect("effects").pinned_work.verdict,
        "refused"
    );
    let error = fixture
        .apply(&candidate(&project, &second, &[]))
        .await
        .expect_err("stranded work is refused");
    assert_eq!(refusal_codes(&error), ["casework.activation.stranded-work"]);
    assert!(error.to_string().contains(&second));
    assert_eq!(fixture.ledger().await.len(), 1);

    let mut acknowledged = candidate(&project, &second, &[]);
    acknowledged.acknowledged_stranded_work = Some(&second);
    let applied = fixture
        .apply(&acknowledged)
        .await
        .expect("the acknowledged package applies");
    assert_eq!(applied.effects.pinned_work.verdict, "acknowledged");
    assert_eq!(fixture.ledger().await.len(), 2);
}

/// Work admitted under the active package after its apply, by a process
/// still serving an earlier package, is refused at startup until the
/// operator acknowledges the package that strands it.
#[tokio::test]
async fn startup_refuses_work_stranded_after_apply_until_the_package_is_acknowledged() {
    let fixture = Fixture::single("stranded_startup").await;
    let project = project();
    let first = digest('a');
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply with no pinned work");
    assert_eq!(applied.effects.pinned_work.verdict, "clear");
    fixture
        .client
        .execute(
            "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,binding,state,queue_id,revision,first_observed_at,updated_at) VALUES($1,'retired-source','request','subject-1','review','review-1',$2,'open','retired-queue',1,now(),now())",
            &[
                &Uuid::new_v4(),
                &json!({"sourceRevision": "1", "version": "proposal-1", "generation": "retired"}),
            ],
        )
        .await
        .expect("an earlier process admits work the active package strands");
    let runtime = fixture.runtime();

    let refused = check_pinned_work(&runtime, &project, &[], &first, None)
        .await
        .expect_err("startup refuses the stranded work");
    assert!(
        matches!(refused, RuntimeError::StrandedPinnedWork(_)),
        "{refused}"
    );
    let message = refused.to_string();
    assert!(message.contains("source retired-source"), "{message}");
    assert!(
        message.contains(&format!("set package.acknowledgeStrandedWork to {first}")),
        "{message}"
    );
    check_pinned_work(&runtime, &project, &[], &first, Some(&digest('b')))
        .await
        .expect_err("an acknowledgement of another package is refused");
    check_pinned_work(&runtime, &project, &[], &first, Some(&first))
        .await
        .expect("the acknowledged package starts");
}

/// A pending migration that would drop hosted work or unpublished audit is
/// named by `plan`, read without a lock, and `apply` refuses the same.
#[tokio::test]
async fn plan_reports_the_destructive_migration_refusals_apply_meets() {
    let fixture = Fixture::single("plan_migration_blockers").await;
    let project = project();
    fixture
        .apply(&candidate(&project, &digest('a'), &[]))
        .await
        .expect("initial apply");
    // The schema of a release before the hosted tables and the audit outbox
    // were dropped, each still holding a row.
    fixture
        .client
        .batch_execute(
            "CREATE TABLE casework_hosted_items (item_id uuid PRIMARY KEY); \
             INSERT INTO casework_hosted_items VALUES('00000000-0000-4000-8000-0000000000a1'); \
             CREATE TABLE casework_audit_outbox (event_id uuid PRIMARY KEY, audit_record jsonb NOT NULL, published_at timestamptz); \
             INSERT INTO casework_audit_outbox(event_id,audit_record) VALUES('00000000-0000-4000-8000-0000000000c1','{}'); \
             DELETE FROM casework_schema_migrations WHERE version>=15;",
        )
        .await
        .expect("simulate the schema before migration 15");
    let successor = digest('b');

    let plan = fixture
        .runtime()
        .plan_activation(&candidate(&project, &successor, &[]))
        .await
        .expect("plan");
    let codes: Vec<&str> = plan
        .refusals
        .iter()
        .map(|refusal| refusal.code.as_str())
        .collect();
    assert_eq!(
        codes,
        [
            "casework.activation.hosted-work-would-be-dropped",
            "casework.activation.unpublished-audit-would-be-dropped"
        ],
        "{:?}",
        plan.refusals
    );
    assert!(!plan.changes_pending);
    assert!(
        plan.refusals[0]
            .message
            .contains("casework_hosted_items (1 row)"),
        "{:?}",
        plan.refusals
    );

    let error = fixture
        .apply(&candidate(&project, &successor, &[]))
        .await
        .expect_err("apply refuses what the plan named");
    assert_eq!(
        refusal_codes(&error),
        [
            "casework.activation.hosted-work-would-be-dropped",
            "casework.activation.unpublished-audit-would-be-dropped"
        ]
    );
    fixture
        .client
        .batch_execute("DELETE FROM casework_hosted_items")
        .await
        .expect("the hosted work is exported");
    let plan = fixture
        .runtime()
        .plan_activation(&candidate(&project, &successor, &[]))
        .await
        .expect("plan");
    let codes: Vec<&str> = plan
        .refusals
        .iter()
        .map(|refusal| refusal.code.as_str())
        .collect();
    assert_eq!(
        codes,
        ["casework.activation.unpublished-audit-would-be-dropped"]
    );
    assert_eq!(fixture.ledger().await.len(), 1);
}

#[tokio::test]
async fn plan_with_the_runtime_credential_before_the_first_split_apply_reports_an_initial_activation(
) {
    let fixture = Fixture::split("plan_split").await;
    let project = project();
    let first = digest('a');
    let runtime = fixture.runtime();
    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("the runtime role plans before any grant");
    assert_eq!(plan.plan_kind, PlanKind::Initial);
    assert!(plan.changes_pending, "{:?}", plan.refusals);
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan after the first apply");
    assert!(!plan.changes_pending, "{:?}", plan.refusals);
    assert_eq!(plan.runtime_role_mode, Some(RoleMode::Split));
    drop(runtime);
    fixture.drop_runtime_role().await;
}

#[tokio::test]
async fn a_runtime_role_that_gained_ledger_authority_is_refused_at_startup_until_apply_records_it()
{
    let fixture = Fixture::split("weakened").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let runtime = fixture.runtime();
    fixture
        .client
        .batch_execute(&format!(
            "GRANT INSERT ON casework_activations TO {}",
            fixture.runtime_user
        ))
        .await
        .expect("grant the runtime role ledger authority");
    let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a split activation whose runtime role can write the ledger is refused");
    assert!(
        matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
        "{weakened}"
    );
    assert!(weakened
        .to_string()
        .contains("caseworkctl apply --runtime-config FILE"));
    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan");
    assert!(plan.changes_pending, "{:?}", plan.refusals);
    assert_eq!(plan.runtime_role_mode, Some(RoleMode::Single));
    let reissued = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply reissues the grants for the active package");
    assert_eq!(reissued.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("the reissued grants start"),
        RoleMode::Split
    );

    // Membership in the migration role is authority a revoke cannot take
    // away, so apply records the activation as single-role.
    let migration_user = fixture
        .migration
        .current_user()
        .await
        .expect("migration role");
    fixture
        .client
        .batch_execute(&format!(
            "GRANT {migration_user} TO {}",
            fixture.runtime_user
        ))
        .await
        .expect("make the runtime role a member of the migration role");
    let member = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply records the runtime role's authority");
    assert_eq!(member.activation.role_mode, RoleMode::Single);
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("a single-role activation starts"),
        RoleMode::Single
    );
    assert_eq!(fixture.ledger().await.len(), 3);
    drop(runtime);
    fixture.drop_runtime_role().await;
}

#[tokio::test]
async fn moving_to_split_and_rotating_the_runtime_role_reapply_the_active_package() {
    let fixture = Fixture::single("rotate").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("single-role apply");
    let (one, one_store) = fixture.login_role().await;
    let moved = fixture
        .apply_as(&one, &candidate(&project, &first, &[]))
        .await
        .expect("moving to split applies the active package again");
    assert_eq!(moved.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&one_store, DATABASE_ID, &first, &[])
            .await
            .expect("the split runtime role starts"),
        RoleMode::Split
    );
    let (two, two_store) = fixture.login_role().await;
    let rotated = fixture
        .apply_as(&two, &candidate(&project, &first, &[]))
        .await
        .expect("a rotated runtime role applies the active package again");
    assert_eq!(rotated.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&two_store, DATABASE_ID, &first, &[])
            .await
            .expect("the rotated runtime role starts"),
        RoleMode::Split
    );
    let error = fixture
        .apply_as(&two, &candidate(&project, &first, &[]))
        .await
        .expect_err("nothing changed since the rotation");
    assert_eq!(
        refusal_codes(&error),
        ["casework.activation.already-active"]
    );
    assert_eq!(fixture.ledger().await.len(), 3);
    drop((one_store, two_store));
    fixture.drop_roles(&[&one, &two]).await;
}

/// A single-role activation whose runtime credential is rotated to a
/// separate role is split by that credential, so startup checks the grants
/// a split apply issues rather than trusting the single-role ledger row.
#[tokio::test]
async fn a_single_role_activation_rotated_to_a_role_without_its_grants_is_refused_at_startup() {
    let fixture = Fixture::single("singlerotate").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("single-role apply");
    let (role, rotated) = fixture.login_role().await;
    fixture
        .client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA {schema} TO {role};
             GRANT SELECT ON casework_activations, casework_schema_migrations,
               casework_source_reconciliation_progress TO {role}",
            schema = fixture.schema
        ))
        .await
        .expect("let the rotated role read the ledgers only");
    let missing = check_activation(&rotated, DATABASE_ID, &first, &[])
        .await
        .expect_err("a split runtime role without its grants is refused");
    assert!(
        matches!(missing, RuntimeError::RuntimeGrantsMissing),
        "{missing}"
    );
    assert!(missing
        .to_string()
        .contains("caseworkctl apply --runtime-config FILE"));

    // A rotated role that can reach the ledger is single-role, as the
    // ledger records, and a split apply for it still refuses that authority.
    fixture
        .client
        .batch_execute(&format!("GRANT TRIGGER ON casework_teams TO {role}"))
        .await
        .expect("grant the rotated role TRIGGER");
    assert_eq!(
        check_activation(&rotated, DATABASE_ID, &first, &[])
            .await
            .expect("a single-role activation starts"),
        RoleMode::Single
    );
    let refused = fixture
        .apply_as(&role, &candidate(&project, &first, &[]))
        .await
        .expect_err("a split apply refuses the rotated role's TRIGGER");
    assert_eq!(
        refusal_codes(&refused),
        ["casework.activation.role-mode-weakened"]
    );
    fixture
        .client
        .batch_execute(&format!("REVOKE TRIGGER ON casework_teams FROM {role}"))
        .await
        .expect("revoke TRIGGER");
    let applied = fixture
        .apply_as(&role, &candidate(&project, &first, &[]))
        .await
        .expect("apply issues the rotated role its grants");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&rotated, DATABASE_ID, &first, &[])
            .await
            .expect("the rotated runtime role starts"),
        RoleMode::Split
    );
    assert_eq!(fixture.ledger().await.len(), 2);
    drop(rotated);
    fixture.drop_roles(&[&role]).await;
}

#[tokio::test]
async fn plan_as_a_rotated_runtime_role_that_cannot_read_the_ledger_names_apply() {
    let fixture = Fixture::single("plan_rotated").await;
    let project = project();
    let first = digest('a');
    let (one, _one_store) = fixture.login_role().await;
    fixture
        .apply_as(&one, &candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let (two, two_store) = fixture.login_role().await;
    let expected = format!(
        "the Casework runtime role cannot read the activation ledger in schema {}; run `caseworkctl apply --runtime-config FILE` to grant the runtime role its privileges, then rerun `caseworkctl plan --runtime-config FILE`",
        fixture.schema
    );

    // Without USAGE on the schema the ledger is invisible, which must not
    // read as an empty database.
    let error = two_store
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect_err("a role that cannot see the ledger is refused");
    assert!(
        matches!(error, StoreError::LedgerUnreadable { .. }),
        "{error:?}"
    );
    assert_eq!(error.to_string(), expected);

    // With USAGE but without SELECT on the ledger tables.
    fixture
        .client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA {} TO {two}",
            fixture.schema
        ))
        .await
        .expect("grant schema usage");
    let error = two_store
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect_err("a role that cannot read the ledger is refused");
    assert_eq!(error.to_string(), expected);

    fixture
        .apply_as(&two, &candidate(&project, &first, &[]))
        .await
        .expect("apply grants the rotated runtime role");
    let plan = two_store
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("the rotated runtime role plans after apply");
    assert!(!plan.changes_pending, "{:?}", plan.refusals);
    drop((_one_store, two_store));
    fixture.drop_roles(&[&one, &two]).await;
}

#[tokio::test]
async fn an_apply_waiting_for_a_runtime_directory_lock_holds_no_migration_lock() {
    let fixture = Fixture::single("lockorder").await;
    let project = project();
    let first = digest('a');
    // A database migrated before the activation ledger existed.
    fixture.migration.migrate().await.expect("migrate");
    fixture
        .client
        .batch_execute(
            "DROP INDEX casework_review_decision_author_position_idx; \
             ALTER TABLE casework_review_accountability DROP COLUMN outcome; \
             DROP INDEX casework_review_task_queue_position_idx; \
             DROP INDEX casework_review_task_assigned_position_idx; \
             DROP INDEX casework_review_accountability_task_idx; \
             DROP TABLE casework_activations; \
             DELETE FROM casework_schema_migrations WHERE version>=19;",
        )
        .await
        .expect("return the schema to version 18");
    let mut holder = connect(&scoped(&base_url(), &fixture.schema)).await;
    let directory = holder
        .transaction()
        .await
        .expect("begin the runtime holder");
    directory
        .query_one(
            "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR SHARE",
            &[],
        )
        .await
        .expect("take the directory lock a runtime transaction takes first");
    let observer = connect(&base_url()).await;
    let observe = async {
        tokio::time::sleep(Duration::from_millis(750)).await;
        // Only relation locks: a row-lock wait also holds a tuple lock in
        // AccessExclusiveLock mode, and that is the wait itself.
        let strong: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname=$1 AND l.locktype='relation' AND l.granted
                   AND l.mode NOT IN ('AccessShareLock','RowShareLock','RowExclusiveLock')",
                &[&fixture.schema],
            )
            .await
            .expect("read the lock table")
            .get(0);
        directory
            .commit()
            .await
            .expect("release the directory lock");
        strong
    };
    let adopting = candidate(&project, &first, &[]);
    let (applied, strong) = tokio::join!(fixture.apply(&adopting), observe);
    assert_eq!(
        strong, 0,
        "apply held a migration lock while it waited for the directory lock"
    );
    let applied = applied.expect("the first apply adopts the migrated database");
    assert_eq!(applied.activation.plan_kind, PlanKind::Initial);
    assert_eq!(applied.schema_versions_applied, [19, 20, 21]);
}

/// A runtime role that owns a Casework table can attach a trigger that fires
/// as the migration role inside apply's own transaction, so it can write the
/// ledger. Split-role apply refuses before it changes anything, and startup
/// refuses the split activation, until the ownership is reassigned.
#[tokio::test]
async fn a_runtime_role_that_owns_a_casework_table_is_refused_by_apply_and_at_startup() {
    let fixture = Fixture::split("owned").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let migration_user = fixture
        .migration
        .current_user()
        .await
        .expect("migration role");
    let runtime_user = fixture.runtime_user.clone();
    let fix = format!("REASSIGN OWNED BY {runtime_user} TO {migration_user}");
    let runtime = fixture.runtime();
    fixture
        .client
        .batch_execute(&format!(
            "ALTER TABLE casework_task_templates OWNER TO {runtime_user}"
        ))
        .await
        .expect("give the runtime role a work table");

    let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a runtime role that owns a Casework table is refused");
    assert!(
        matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
        "{weakened}"
    );
    let message = weakened.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(
        message.contains("caseworkctl apply --runtime-config FILE"),
        "{message}"
    );

    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan");
    assert!(!plan.changes_pending);
    assert_eq!(plan.runtime_role_mode, Some(RoleMode::Single));
    assert!(
        plan.refusals.iter().any(|refusal| {
            refusal.code == "casework.activation.role-mode-weakened"
                && refusal.message.contains(&fix)
        }),
        "{:?}",
        plan.refusals
    );

    let second = digest('b');
    let refused = fixture
        .apply(&candidate(&project, &second, &[]))
        .await
        .expect_err("split-role apply refuses a runtime role that owns a Casework table");
    assert_eq!(
        refusal_codes(&refused),
        ["casework.activation.role-mode-weakened"]
    );
    let message = refused.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(
        message.contains("caseworkctl apply --runtime-config FILE"),
        "{message}"
    );
    assert_eq!(fixture.ledger().await.len(), 1, "apply recorded nothing");

    fixture
        .client
        .batch_execute(&fix)
        .await
        .expect("reassign the runtime role's objects");

    // Taking the table back also took the runtime role's grants on it, so
    // startup refuses until apply reissues them, and the active package is
    // pending again rather than already active.
    let missing = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a split activation whose runtime role lost its grants is refused");
    assert!(
        matches!(missing, RuntimeError::RuntimeGrantsMissing),
        "{missing}"
    );
    assert!(missing
        .to_string()
        .contains("caseworkctl apply --runtime-config FILE"));
    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan");
    assert!(plan.changes_pending, "{:?}", plan.refusals);
    assert_eq!(plan.runtime_role_mode, Some(RoleMode::Split));
    assert!(
        plan.effects.is_none(),
        "the runtime role cannot read the reassigned table until apply"
    );
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply reissues the grants after the reassignment");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("the reassigned split activation starts"),
        RoleMode::Split
    );
    connect(&fixture.runtime_url)
        .await
        .batch_execute(
            "SELECT count(*) FROM casework_task_templates;
             INSERT INTO casework_task_templates SELECT * FROM casework_task_templates WHERE false;
             UPDATE casework_task_templates SET active=active WHERE false;
             DELETE FROM casework_task_templates WHERE false",
        )
        .await
        .expect("the runtime role writes its work table again");
    drop(runtime);
    fixture.drop_runtime_role().await;
}

/// CREATE on the Casework schema lets the runtime role create objects there,
/// so split-role apply refuses it before it changes anything, and startup
/// refuses a split activation whose runtime role gained it.
#[tokio::test]
async fn a_runtime_role_with_create_on_the_schema_is_refused_by_apply_and_at_startup() {
    let fixture = Fixture::split("create").await;
    let project = project();
    let first = digest('a');
    let runtime_user = fixture.runtime_user.clone();
    let grant = format!(
        "GRANT CREATE ON SCHEMA {} TO {runtime_user}",
        fixture.schema
    );
    let fix = format!(
        "REVOKE CREATE ON SCHEMA {} FROM {runtime_user}",
        fixture.schema
    );
    fixture
        .client
        .batch_execute(&grant)
        .await
        .expect("grant the runtime role schema CREATE");

    let refused = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect_err("split-role apply refuses a runtime role with schema CREATE");
    assert_eq!(
        refusal_codes(&refused),
        ["casework.activation.role-mode-weakened"]
    );
    let message = refused.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(message.contains(REVOKE_NEXT), "{message}");
    assert_eq!(fixture.relation_count().await, 0, "apply changed nothing");

    fixture
        .client
        .batch_execute(&fix)
        .await
        .expect("revoke schema CREATE");
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply after the revoke");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);

    let runtime = fixture.runtime();
    fixture
        .client
        .batch_execute(&grant)
        .await
        .expect("grant schema CREATE again");
    let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a split activation whose runtime role can create objects is refused");
    assert!(
        matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
        "{weakened}"
    );
    let message = weakened.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(message.contains(REVOKE_NEXT), "{message}");
    drop(runtime);
    fixture.drop_runtime_role().await;
}

/// A default privilege would hand the runtime role TRIGGER on every table a
/// migration creates. Apply does not take it away: it refuses before any
/// migration, naming the default privilege to revoke, since the tables a
/// later refusal would name do not survive its rollback.
#[tokio::test]
async fn a_default_trigger_privilege_for_the_runtime_role_is_refused_before_any_migration() {
    let fixture = Fixture::split("default_trigger").await;
    let project = project();
    let first = digest('a');
    let runtime_user = fixture.runtime_user.clone();
    let migration_role = fixture
        .migration
        .current_user()
        .await
        .expect("migration role");
    let schema = fixture.schema.clone();
    fixture
        .client
        .batch_execute(&format!(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA {schema} GRANT TRIGGER ON TABLES TO {runtime_user}"
        ))
        .await
        .expect("grant the runtime role TRIGGER by default");
    let fix = format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {migration_role} IN SCHEMA {schema} \
         REVOKE TRIGGER ON TABLES FROM {runtime_user}"
    );

    let refused = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect_err("split-role apply refuses a default TRIGGER privilege");
    assert_eq!(
        refusal_codes(&refused),
        ["casework.activation.role-mode-weakened"]
    );
    let message = refused.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(message.contains(REVOKE_NEXT), "{message}");
    assert_eq!(fixture.relation_count().await, 0, "apply changed nothing");

    fixture
        .client
        .batch_execute(&fix)
        .await
        .expect("revoke the default TRIGGER privilege");
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply after the revoke");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    fixture.drop_runtime_role().await;
}

/// Writing the schema-migration ledger is authority over the activation
/// ledger as much as writing it, so startup refuses the split activation,
/// and apply takes the privilege back. A column-level INSERT or UPDATE, or
/// TRUNCATE, on either ledger counts as a write the same way.
#[tokio::test]
async fn ledger_writes_weaken_a_split_activation_until_apply_revokes_them() {
    let fixture = Fixture::split("ledgerwrite").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let runtime = fixture.runtime();
    for grant in [
        "GRANT INSERT ON casework_schema_migrations TO {role}",
        "GRANT UPDATE ON casework_schema_migrations TO {role}",
        "GRANT INSERT (version) ON casework_schema_migrations TO {role}",
        "GRANT TRUNCATE ON casework_schema_migrations TO {role}",
        "GRANT UPDATE (package_digest) ON casework_activations TO {role}",
        "GRANT INSERT (activation_id) ON casework_activations TO {role}",
        "GRANT TRUNCATE ON casework_activations TO {role}",
    ] {
        fixture
            .client
            .batch_execute(&grant.replace("{role}", &fixture.runtime_user))
            .await
            .expect("grant the runtime role a privilege");
        let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect_err("the privilege weakens the split activation");
        assert!(
            matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
            "{grant}: {weakened}"
        );
        assert!(weakened
            .to_string()
            .contains("caseworkctl apply --runtime-config FILE"));
        let reissued = fixture
            .apply(&candidate(&project, &first, &[]))
            .await
            .expect("apply reissues the grants");
        assert_eq!(reissued.activation.role_mode, RoleMode::Split, "{grant}");
        assert_eq!(
            check_activation(&runtime, DATABASE_ID, &first, &[])
                .await
                .expect("the reissued grants start"),
            RoleMode::Split
        );
    }
    drop(runtime);
    fixture.drop_runtime_role().await;
}

/// The next action every `REVOKE` or `DROP TRIGGER` fix ends with.
const REVOKE_NEXT: &str =
    "then rerun the command that refused, or `caseworkctl plan --runtime-config FILE` to confirm";

/// TRIGGER on a Casework table, and CREATE on the schema held through
/// `PUBLIC`, let the runtime role attach code that runs as the migration
/// role. Each is refused at startup and by split-role apply, naming the
/// revoke from whoever holds it.
#[tokio::test]
async fn trigger_and_public_privileges_are_refused_naming_their_revoke() {
    let fixture = Fixture::split("revoke").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let runtime = fixture.runtime();
    let schema = fixture.schema.clone();
    let role = fixture.runtime_user.clone();
    for (grant, fix) in [
        (
            format!("GRANT TRIGGER ON casework_teams TO {role}"),
            format!("REVOKE TRIGGER ON {schema}.casework_teams FROM {role}"),
        ),
        (
            "GRANT TRIGGER ON casework_teams TO PUBLIC".to_owned(),
            format!("REVOKE TRIGGER ON {schema}.casework_teams FROM PUBLIC"),
        ),
        (
            format!("GRANT CREATE ON SCHEMA {schema} TO PUBLIC"),
            format!("REVOKE CREATE ON SCHEMA {schema} FROM PUBLIC"),
        ),
    ] {
        fixture
            .client
            .batch_execute(&grant)
            .await
            .expect("grant a weakening privilege");
        let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect_err("the privilege weakens the split activation");
        assert!(
            matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
            "{grant}: {weakened}"
        );
        let message = weakened.to_string();
        assert!(message.contains(&fix), "{grant}: {message}");
        assert!(message.contains(REVOKE_NEXT), "{grant}: {message}");
        let refused = fixture
            .apply(&candidate(&project, &digest('b'), &[]))
            .await
            .expect_err("split-role apply refuses the privilege");
        assert_eq!(
            refusal_codes(&refused),
            ["casework.activation.role-mode-weakened"],
            "{grant}"
        );
        assert!(refused.to_string().contains(&fix), "{grant}: {refused}");
        assert_eq!(fixture.ledger().await.len(), 1, "{grant}");
        fixture
            .client
            .batch_execute(&fix)
            .await
            .expect("revoke the privilege");
        assert_eq!(
            check_activation(&runtime, DATABASE_ID, &first, &[])
                .await
                .expect("the split activation starts after the revoke"),
            RoleMode::Split,
            "{grant}"
        );
    }
    drop(runtime);
    fixture.drop_runtime_role().await;
}

/// A trigger no Casework migration creates runs as whichever role fires it,
/// the migration role inside apply included, and it outlives the ownership
/// its author held. Split-role apply, plan, and startup refuse it by name
/// until it is dropped.
#[tokio::test]
async fn a_trigger_left_by_a_runtime_role_that_owned_a_table_is_refused_after_reassignment() {
    let fixture = Fixture::split("trigger").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("split-role apply");
    let migration_user = fixture
        .migration
        .current_user()
        .await
        .expect("migration role");
    let schema = fixture.schema.clone();
    let role = fixture.runtime_user.clone();
    fixture
        .client
        .batch_execute(&format!(
            "CREATE FUNCTION stray_touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$;
             ALTER TABLE casework_teams OWNER TO {role}"
        ))
        .await
        .expect("give the runtime role a work table");
    connect(&fixture.runtime_url)
        .await
        .batch_execute(
            "CREATE TRIGGER stray_touch AFTER INSERT ON casework_teams FOR EACH ROW EXECUTE FUNCTION stray_touch()",
        )
        .await
        .expect("the owning runtime role attaches a trigger");
    fixture
        .client
        .batch_execute(&format!("REASSIGN OWNED BY {role} TO {migration_user}"))
        .await
        .expect("reassign the runtime role's objects");
    let fix = format!("DROP TRIGGER stray_touch ON {schema}.casework_teams");

    let runtime = fixture.runtime();
    let weakened = check_activation(&runtime, DATABASE_ID, &first, &[])
        .await
        .expect_err("a stray trigger weakens the split activation");
    assert!(
        matches!(weakened, RuntimeError::RoleModeWeakened { .. }),
        "{weakened}"
    );
    let message = weakened.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(message.contains(REVOKE_NEXT), "{message}");
    let plan = runtime
        .plan_activation(&candidate(&project, &first, &[]))
        .await
        .expect("plan");
    assert!(!plan.changes_pending);
    assert!(
        plan.refusals.iter().any(|refusal| {
            refusal.code == "casework.activation.role-mode-weakened"
                && refusal.message.contains(&fix)
        }),
        "{:?}",
        plan.refusals
    );
    let refused = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect_err("split-role apply refuses the stray trigger");
    assert_eq!(
        refusal_codes(&refused),
        ["casework.activation.role-mode-weakened"]
    );
    let message = refused.to_string();
    assert!(message.contains(&fix), "{message}");
    assert!(message.contains(REVOKE_NEXT), "{message}");
    assert_eq!(fixture.ledger().await.len(), 1, "apply recorded nothing");

    fixture
        .client
        .batch_execute(&fix)
        .await
        .expect("drop the stray trigger");
    let applied = fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("apply reissues the grants once the trigger is gone");
    assert_eq!(applied.activation.role_mode, RoleMode::Split);
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("the split activation starts"),
        RoleMode::Split
    );
    drop(runtime);
    fixture.drop_runtime_role().await;
}

/// A single-role deployment already holds the ledger, so a trigger it adds
/// to a Casework table refuses nothing.
#[tokio::test]
async fn a_trigger_on_a_casework_table_refuses_no_single_role_apply() {
    let fixture = Fixture::single("singletrigger").await;
    let project = project();
    let first = digest('a');
    fixture
        .apply(&candidate(&project, &first, &[]))
        .await
        .expect("single-role apply");
    fixture
        .client
        .batch_execute(
            "CREATE FUNCTION stray_touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$;
             CREATE TRIGGER stray_touch AFTER INSERT ON casework_teams FOR EACH ROW EXECUTE FUNCTION stray_touch()",
        )
        .await
        .expect("attach a trigger");
    let runtime = fixture.runtime();
    assert_eq!(
        check_activation(&runtime, DATABASE_ID, &first, &[])
            .await
            .expect("a single-role activation starts"),
        RoleMode::Single
    );
    let plan = runtime
        .plan_activation(&candidate(&project, &digest('b'), &[]))
        .await
        .expect("plan");
    assert!(plan.changes_pending, "{:?}", plan.refusals);
    fixture
        .apply(&candidate(&project, &digest('b'), &[]))
        .await
        .expect("single-role apply ignores the trigger");
}

/// `serve` itself refuses a migrated database no package was applied to:
/// it returns the refusal, never listens, and writes no Casework row.
#[tokio::test]
async fn serve_refuses_an_unapplied_database_before_listening_or_writing() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::single("serve").await;
    fixture
        .migration
        .migrate()
        .await
        .expect("migrate without activating");
    let rows = casework_row_counts(&fixture).await;
    assert!(!rows.is_empty());

    let root = tempfile::tempdir_in(
        std::fs::canonicalize(env::temp_dir()).expect("canonical temporary directory"),
    )
    .expect("temporary directory");
    let package = root.path().join("package");
    std::fs::create_dir(&package).expect("package directory");
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/casework/examples/standalone-decision/casework.yaml"
        ),
        package.join("casework.yaml"),
    )
    .expect("copy the project");
    registry_platform_config::write_sum_file(
        &package,
        None,
        &registry_casework::package_limits(),
        registry_casework::PACKAGE_COMMAND,
    )
    .expect("package the project");
    let secrets = root.path().join("secrets");
    std::fs::create_dir(&secrets).expect("secrets directory");
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))
        .expect("secrets directory mode");
    let audit_key = secrets.join("audit");
    std::fs::write(&audit_key, [7_u8; 32]).expect("audit key");
    std::fs::set_permissions(&audit_key, std::fs::Permissions::from_mode(0o600))
        .expect("audit key mode");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("reserved address")
        .port();
    let runtime = root.path().join("runtime.yaml");
    std::fs::write(
        &runtime,
        serde_json::to_string_pretty(&json!({
            "apiVersion": "id.registrystack.org/formats/casework/runtime/v1alpha1",
            "kind": "CaseworkRuntimeConfig",
            "identity": {"databaseId": DATABASE_ID},
            "package": {"root": package},
            "listener": {
                "bind": format!("127.0.0.1:{port}"),
                "tlsTermination": "development-loopback",
                "networkExposure": "private-address"
            },
            "secretProviders": {"file": {"root": secrets}, "environment": {}},
            "database": {
                "runtimeUrlRef": fixture.database.runtime_url_ref,
                "migrationUrlRef": fixture.database.migration_url_ref,
                "testOnlyPlaintext": true
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:casework",
                "allowedClients": "unrestricted"
            }},
            "audit": {"path": root.path().join("audit.ndjson"), "hashKeyRef": "secret:file/audit"},
            "sources": {}
        }))
        .expect("render the runtime configuration"),
    )
    .expect("write the runtime configuration");

    let refused = tokio::time::timeout(
        Duration::from_secs(30),
        registry_casework::serve_from_path(&runtime),
    )
    .await
    .expect("serve returns instead of serving")
    .expect_err("serve refuses an unapplied database");
    assert!(matches!(refused, RuntimeError::NotActivated), "{refused}");
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err(),
        "serve never listened"
    );
    assert_eq!(
        casework_row_counts(&fixture).await,
        rows,
        "serve wrote no row"
    );
}

/// The row count of every Casework table in the fixture's schema.
async fn casework_row_counts(fixture: &Fixture) -> Vec<(String, i64)> {
    let tables: Vec<String> = fixture
        .client
        .query(
            "SELECT format('%I.%I', n.nspname, c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname=$1 AND c.relname LIKE 'casework\\_%' AND c.relkind IN ('r','p') ORDER BY 1",
            &[&fixture.schema],
        )
        .await
        .expect("list Casework tables")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let mut counts = Vec::new();
    for table in tables {
        let count: i64 = fixture
            .client
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .expect("count rows")
            .get(0);
        counts.push((table, count));
    }
    counts
}
