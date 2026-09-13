// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use registry_casework::{
    router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState, HumanIdentityConfig,
    PostgresStore, ServiceError, StoreError,
};
use registry_casework_core::{
    standalone_decision_starter_kind, AccessProfile, ActiveSubjectsPage, ActorContext,
    AttemptState, AuthoritativeObservation, BootstrapDirectoryRequest, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, DiscoveryCursor, EphemeralCredential,
    EventRequest, ExecutePreparedRequest, InboxPolicy, InboxView, IssuerPrincipal, OccurrenceKind,
    OccurrenceState, OperationName, PageStatus, PrepareActionRequest, PreparedSourceAttempt,
    QueuePolicy, RecoveryEvidence, SourceAdapter, SourceAdapterError, SourceBinding, SourcePolicy,
    SourceReceipt, SourceRequestPolicy, SubjectRef, TransitionHint, ATTEMPT_REFERENCE_HEADER,
    CASEWORK_API_VERSION, CASEWORK_KIND, CASEWORK_PROFILE_HEADER, IDEMPOTENCY_KEY_HEADER,
    IF_MATCH_HEADER, SOURCE_PROFILE_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde_json::json;
use tokio::sync::Notify;
use tokio_postgres::NoTls;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

const DATABASE_ENV: &str = "CASEWORK_VISIBILITY_TEST_DATABASE_URL";
const SOURCE_ID: &str = "registry";
const ENTITY: &str = "correction";
const QUEUE: &str = "default";
const GENERATION: &str = "generation-1";
const DISCLOSURE_CANARY: &str = "SOURCE-DISCLOSURE-MUST-NOT-ENTER-INBOX";
const TOKEN_ISSUER: &str = "https://issuer.example";
const TOKEN_AUDIENCE: &str = "registry-casework";
const TOKEN_KID: &str = "casework-test-key";
const TOKEN_SECRET: &[u8] = b"01234567890123456789012345678901";
const TOKEN_SECRET_BASE64URL: &str = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE";

/// Every suite in this binary resets the dedicated visibility database, so the
/// suites take this lock for their whole body and run one at a time.
static DATABASE: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

#[derive(Clone)]
enum CallerRead {
    Visible(&'static str),
    Routing {
        reason: &'static str,
        readable_fields: &'static [&'static str],
    },
    Concealed,
    Unavailable,
    Delayed(Duration),
}

struct ActiveCallerRead {
    active: Arc<AtomicUsize>,
}

struct DiscoveryGate {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
    first_subject: SubjectRef,
    first_fails: bool,
}

impl Drop for ActiveCallerRead {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct MockSource {
    generation: String,
    reads: HashMap<String, CallerRead>,
    caller_read_calls: Arc<AtomicUsize>,
    active_caller_reads: Arc<AtomicUsize>,
    peak_caller_reads: Arc<AtomicUsize>,
    caller_unavailable_after: Option<usize>,
    prepare_calls: Arc<AtomicUsize>,
    terminal_read: Option<String>,
    discovery_unavailable: Arc<AtomicBool>,
    discovery_pages: Option<(Uuid, Uuid)>,
    discovery_total: Option<usize>,
    discovery_cursors: Arc<Mutex<Vec<Option<String>>>>,
    discovery_gate: Option<Arc<DiscoveryGate>>,
    open_reads: HashSet<String>,
    attachment_verification: Option<(String, Arc<AtomicBool>)>,
    verify_diagnostic_events: bool,
    execute_calls: Arc<AtomicUsize>,
    execute_succeeds: bool,
    advance_binding_on_success: bool,
    execution_error_after: Option<(usize, SourceAdapterError)>,
    approve_reads: HashSet<String>,
}

impl MockSource {
    fn with_reads(reads: impl IntoIterator<Item = (Uuid, CallerRead)>) -> Self {
        Self {
            generation: GENERATION.to_owned(),
            reads: reads
                .into_iter()
                .map(|(id, read)| (id.to_string(), read))
                .collect(),
            caller_read_calls: Arc::new(AtomicUsize::new(0)),
            active_caller_reads: Arc::new(AtomicUsize::new(0)),
            peak_caller_reads: Arc::new(AtomicUsize::new(0)),
            caller_unavailable_after: None,
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            terminal_read: None,
            discovery_unavailable: Arc::new(AtomicBool::new(false)),
            discovery_pages: None,
            discovery_total: None,
            discovery_cursors: Arc::new(Mutex::new(Vec::new())),
            discovery_gate: None,
            open_reads: HashSet::new(),
            attachment_verification: None,
            verify_diagnostic_events: false,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            execute_succeeds: false,
            advance_binding_on_success: false,
            execution_error_after: None,
            approve_reads: HashSet::new(),
        }
    }

    fn with_successful_action(
        id: Uuid,
        read: CallerRead,
    ) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let mut source = Self::with_reads([(id, read)]);
        source.execute_succeeds = true;
        source.approve_reads.insert(id.to_string());
        let prepare_calls = Arc::clone(&source.prepare_calls);
        let execute_calls = Arc::clone(&source.execute_calls);
        (source, prepare_calls, execute_calls)
    }

    fn with_successful_binding_change(id: Uuid) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let (mut source, prepare_calls, execute_calls) =
            Self::with_successful_action(id, CallerRead::Visible("authorized"));
        source.advance_binding_on_success = true;
        (source, prepare_calls, execute_calls)
    }

    fn with_post_write_read_failure(id: Uuid) -> (Self, Arc<AtomicUsize>) {
        let (mut source, _, execute_calls) =
            Self::with_successful_action(id, CallerRead::Visible("authorized"));
        source.caller_unavailable_after = Some(1);
        (source, execute_calls)
    }

    fn with_recovery_definitive_refusal(id: Uuid, read: CallerRead) -> (Self, Arc<AtomicUsize>) {
        let mut source = Self::with_reads([(id, read)]);
        source.execution_error_after = Some((1, SourceAdapterError::ActionNotOffered));
        source.approve_reads.insert(id.to_string());
        let execute_calls = Arc::clone(&source.execute_calls);
        (source, execute_calls)
    }

    fn with_action_error(id: Uuid, error: SourceAdapterError) -> Self {
        let mut source = Self::with_reads([(id, CallerRead::Visible("authorized"))]);
        source.execution_error_after = Some((0, error));
        source.approve_reads.insert(id.to_string());
        source
    }

    fn with_unavailable_discovery_and_terminal_read(id: Uuid) -> Self {
        let mut source = Self::with_unavailable_discovery();
        source.terminal_read = Some(id.to_string());
        source
    }

    fn with_unavailable_discovery() -> Self {
        let source = Self::with_reads([]);
        source.discovery_unavailable.store(true, Ordering::SeqCst);
        source
    }

    fn with_discovery_control() -> (Self, Arc<AtomicBool>) {
        let source = Self::with_reads([]);
        let unavailable = Arc::clone(&source.discovery_unavailable);
        (source, unavailable)
    }

    fn with_multipage_discovery(first: Uuid, second: Uuid) -> Self {
        let mut source = Self::with_reads([
            (first, CallerRead::Concealed),
            (second, CallerRead::Visible("second-page")),
        ]);
        source.discovery_pages = Some((first, second));
        source.open_reads = HashSet::from([first.to_string(), second.to_string()]);
        source
    }

    fn with_large_discovery(total: usize) -> (Self, Arc<Mutex<Vec<Option<String>>>>) {
        let mut source = Self::with_reads([]);
        source.discovery_total = Some(total);
        source.open_reads = (1..=total)
            .map(|value| Uuid::from_u128(value as u128).to_string())
            .collect();
        let cursors = Arc::clone(&source.discovery_cursors);
        (source, cursors)
    }

    fn with_blocked_first_discovery(id: Uuid, first_fails: bool) -> (Self, Arc<DiscoveryGate>) {
        let mut source = Self::with_reads([]);
        let first_subject = subject(id);
        source.open_reads.insert(first_subject.id.clone());
        let gate = Arc::new(DiscoveryGate {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
            first_subject,
            first_fails,
        });
        source.discovery_gate = Some(Arc::clone(&gate));
        (source, gate)
    }

    fn with_generation(mut self, generation: &str) -> Self {
        self.generation = generation.to_owned();
        self
    }

    fn with_attachment_verification(id: Uuid) -> (Self, Arc<AtomicBool>) {
        let mut source = Self::with_reads([]);
        let verified = Arc::new(AtomicBool::new(false));
        source.attachment_verification = Some((id.to_string(), Arc::clone(&verified)));
        (source, verified)
    }

    fn with_diagnostic_events() -> Self {
        let mut source = Self::with_reads([]);
        source.verify_diagnostic_events = true;
        source
    }

    fn visible(subject: &SubjectRef, disclosure: &'static str) -> CallerSubjectView {
        CallerSubjectView {
            display_reference: None,
            subject: subject.clone(),
            binding: binding(),
            disclosed: BTreeMap::from([("summary".into(), json!(disclosure))]),
            permitted_operations: Vec::new(),
        }
    }
}

#[async_trait]
impl SourceAdapter for MockSource {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    fn binding_generation(&self) -> &str {
        &self.generation
    }

    async fn verify_transition(
        &self,
        request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        let deduplication_key = match request.body.as_slice() {
            b"direct-event" if self.verify_diagnostic_events => "diagnostic-direct",
            b"http-event" if self.verify_diagnostic_events => "diagnostic-http",
            _ => return Err(SourceAdapterError::Invalid),
        };
        Ok(TransitionHint {
            subject: SubjectRef {
                source_id: SOURCE_ID.into(),
                kind: ENTITY.into(),
                id: "diagnostic-subject-must-not-be-logged".into(),
            },
            deduplication_key: deduplication_key.into(),
            ordered_revision: 7,
        })
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        if let Some((id, verified)) = &self.attachment_verification {
            if id == &subject.id {
                let verified = verified.load(Ordering::SeqCst);
                return Ok(AuthoritativeObservation {
                    display_reference: None,
                    submitted_at: None,
                    stage_entered_at: None,
                    review_timing: None,
                    routing_context: None,
                    subject: subject.clone(),
                    occurrence_key: "review:1".into(),
                    ordered_revision: 1,
                    binding: binding(),
                    representation_etag: if verified {
                        "\"request-1-attachment-verified\"".into()
                    } else {
                        "\"request-1-attachment-pending\"".into()
                    },
                    occurrence_kind: OccurrenceKind::Review,
                    stage: Some("review".into()),
                    state: OccurrenceState::Open,
                    remaining_actions: verified
                        .then(|| OperationName::parse("approve").expect("approve operation"))
                        .into_iter()
                        .collect(),
                });
            }
        }
        if self.terminal_read.as_deref() != Some(subject.id.as_str()) {
            if !self.open_reads.contains(&subject.id) {
                return Err(SourceAdapterError::Invalid);
            }
            return Ok(AuthoritativeObservation {
                display_reference: None,
                submitted_at: None,
                stage_entered_at: None,
                review_timing: None,
                routing_context: None,
                subject: subject.clone(),
                occurrence_key: "review:1".into(),
                ordered_revision: 1,
                binding: binding(),
                representation_etag: "\"request-1\"".into(),
                occurrence_kind: OccurrenceKind::Review,
                stage: Some("review".into()),
                state: OccurrenceState::Open,
                remaining_actions: Vec::new(),
            });
        }
        let mut terminal_binding = binding();
        terminal_binding.source_revision = "2".into();
        Ok(AuthoritativeObservation {
            display_reference: None,
            submitted_at: None,
            stage_entered_at: None,
            review_timing: None,
            routing_context: None,
            subject: subject.clone(),
            occurrence_key: "review:1".into(),
            ordered_revision: 2,
            binding: terminal_binding,
            representation_etag: "\"request-2\"".into(),
            occurrence_kind: OccurrenceKind::Review,
            stage: Some("review".into()),
            state: OccurrenceState::Completed,
            remaining_actions: Vec::new(),
        })
    }

    async fn discover_active(
        &self,
        cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        self.discovery_cursors
            .lock()
            .expect("discovery cursor lock")
            .push(cursor.map(|value| value.0.clone()));
        if let Some(gate) = &self.discovery_gate {
            if gate.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                gate.entered.notify_one();
                gate.release.notified().await;
                if gate.first_fails {
                    return Err(SourceAdapterError::Unavailable);
                }
                return Ok(ActiveSubjectsPage {
                    subjects: vec![gate.first_subject.clone()],
                    next_cursor: None,
                });
            }
            return Ok(ActiveSubjectsPage {
                subjects: Vec::new(),
                next_cursor: None,
            });
        }
        if self.discovery_unavailable.load(Ordering::SeqCst) {
            Err(SourceAdapterError::Unavailable)
        } else if let Some(total) = self.discovery_total {
            let offset = cursor
                .map_or(Ok(0), |cursor| cursor.0.parse::<usize>())
                .map_err(|_| SourceAdapterError::Invalid)?;
            let end = (offset + 100).min(total);
            Ok(ActiveSubjectsPage {
                subjects: (offset + 1..=end)
                    .map(|value| subject(Uuid::from_u128(value as u128)))
                    .collect(),
                next_cursor: (end < total).then(|| DiscoveryCursor(end.to_string())),
            })
        } else if let Some((first, second)) = self.discovery_pages {
            match cursor.map(|cursor| cursor.0.as_str()) {
                None => Ok(ActiveSubjectsPage {
                    subjects: vec![subject(first)],
                    next_cursor: Some(DiscoveryCursor("page-2".into())),
                }),
                Some("page-2") => Ok(ActiveSubjectsPage {
                    subjects: vec![subject(second)],
                    next_cursor: None,
                }),
                Some(_) => Err(SourceAdapterError::Invalid),
            }
        } else {
            Ok(ActiveSubjectsPage {
                subjects: Vec::new(),
                next_cursor: None,
            })
        }
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _source_profile_id: &str,
        credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        let active = self.active_caller_reads.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_caller_reads.fetch_max(active, Ordering::SeqCst);
        let _active_read = ActiveCallerRead {
            active: Arc::clone(&self.active_caller_reads),
        };
        let read_index = self.caller_read_calls.fetch_add(1, Ordering::SeqCst);
        if self
            .caller_unavailable_after
            .is_some_and(|threshold| read_index >= threshold)
        {
            return Err(SourceAdapterError::Unavailable);
        }
        let credential = credential.expose();
        if credential == "concealed-token" {
            return Err(SourceAdapterError::Concealed);
        }
        if credential == "unavailable-token" {
            return Err(SourceAdapterError::Unavailable);
        }
        if credential == "original-binding-token" {
            let mut view = Self::visible(subject, "original-binding");
            view.permitted_operations
                .push(OperationName::parse("approve").expect("approve operation"));
            return Ok(view);
        }
        if credential == "moved-generation-token" {
            let mut view = Self::visible(subject, "moved-generation");
            view.binding.generation = "generation-2".into();
            return Ok(view);
        }
        if let Some(component) = credential.strip_prefix("moved-binding-") {
            let mut view = Self::visible(subject, "moved-binding");
            match component {
                "revision" => view.binding.source_revision = "2".into(),
                "version" => view.binding.version = "2".into(),
                "integrity" => view.binding.integrity = Some("sha256:moved".into()),
                _ => return Err(SourceAdapterError::Invalid),
            }
            view.permitted_operations
                .push(OperationName::parse("approve").expect("approve operation"));
            return Ok(view);
        }
        if credential == "advanced-terminal-binding" {
            let mut view = Self::visible(subject, "advanced-terminal");
            view.binding.source_revision = "3".into();
            view.binding.version = "2".into();
            view.binding.integrity = Some("sha256:advanced".into());
            return Ok(view);
        }
        if self.advance_binding_on_success && self.execute_calls.load(Ordering::SeqCst) > 0 {
            let mut view = Self::visible(subject, "advanced-by-action");
            view.binding = advanced_action_binding();
            return Ok(view);
        }
        if let Some((id, verified)) = &self.attachment_verification {
            if id == &subject.id {
                let mut view = Self::visible(subject, "attachment");
                if verified.load(Ordering::SeqCst) {
                    view.permitted_operations
                        .push(OperationName::parse("approve").expect("approve operation"));
                }
                return Ok(view);
            }
        }
        match self.reads.get(&subject.id) {
            Some(CallerRead::Visible(disclosure)) => {
                let mut view = Self::visible(subject, disclosure);
                if self.approve_reads.contains(&subject.id) {
                    view.permitted_operations
                        .push(OperationName::parse("approve").expect("approve operation"));
                }
                Ok(view)
            }
            Some(CallerRead::Routing {
                reason,
                readable_fields,
            }) => Ok(CallerSubjectView {
                display_reference: None,
                subject: subject.clone(),
                binding: binding(),
                disclosed: BTreeMap::from([
                    ("reasons".into(), json!([reason])),
                    ("readableFields".into(), json!(readable_fields)),
                ]),
                permitted_operations: vec![OperationName::parse("request_correction")
                    .expect("request correction operation")],
            }),
            Some(CallerRead::Concealed) => Err(SourceAdapterError::Concealed),
            Some(CallerRead::Unavailable) => Err(SourceAdapterError::Unavailable),
            Some(CallerRead::Delayed(delay)) => {
                tokio::time::sleep(*delay).await;
                Ok(Self::visible(subject, "delayed"))
            }
            None => Err(SourceAdapterError::Concealed),
        }
    }

    async fn prepare_action(
        &self,
        request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        if request.reason.is_some() && matches!(request.operation.as_str(), "approve" | "apply") {
            return Err(SourceAdapterError::ReasonUnsupported);
        }
        Ok(PreparedSourceAttempt {
            source_binding: request.displayed_binding.clone(),
            recovery_evidence: RecoveryEvidence::new(vec![1])?,
        })
    }

    async fn execute_prepared(
        &self,
        request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        let call_index = self.execute_calls.fetch_add(1, Ordering::SeqCst);
        if let Some((threshold, error)) = self.execution_error_after {
            if call_index >= threshold {
                return Err(error);
            }
        }
        if !self.execute_succeeds {
            return Err(SourceAdapterError::Invalid);
        }
        let mut resulting_binding = request.prepared.source_binding.clone();
        if self.advance_binding_on_success {
            resulting_binding = advanced_action_binding();
        }
        Ok(SourceReceipt {
            source_revision: "2".into(),
            resulting_state: "needs_changes".into(),
            binding: resulting_binding,
            actor_reference: None,
            metadata: BTreeMap::new(),
        })
    }
}

fn subject(id: Uuid) -> SubjectRef {
    SubjectRef {
        source_id: SOURCE_ID.into(),
        kind: ENTITY.into(),
        id: id.to_string(),
    }
}

struct Fixture {
    service: CaseworkService,
    database: tokio_postgres::Client,
    staff: ActorContext,
    supervisor: ActorContext,
    outsider: ActorContext,
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log capture").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        CapturedLogWriter(Arc::clone(&self.0))
    }
}

impl CapturedLogs {
    fn entries(&self) -> Vec<serde_json::Value> {
        String::from_utf8(self.0.lock().expect("log capture").clone())
            .expect("JSON logs are UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("structured tracing entry"))
            .collect()
    }
}

async fn reset_database() {
    let url = std::env::var(DATABASE_ENV).expect("dedicated visibility test database URL");
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .expect("connect to dedicated visibility test database");
    let driver = tokio::spawn(connection);
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .await
        .expect("reset only the dedicated visibility test database");
    drop(client);
    driver
        .await
        .expect("database connection task")
        .expect("database connection closes cleanly");
}

async fn fixture(
    reads: impl IntoIterator<Item = (Uuid, CallerRead)>,
    inbox: InboxPolicy,
) -> Fixture {
    fixture_with_source(MockSource::with_reads(reads), inbox).await
}

async fn fixture_with_source(source: MockSource, inbox: InboxPolicy) -> Fixture {
    reset_database().await;
    let resolver = SecretResolver::new([SecretProvider::Environment], "/")
        .expect("environment-only secret resolver");
    let database = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{DATABASE_ENV}"),
        migration_url_ref: format!("secret:env/{DATABASE_ENV}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration = PostgresStore::connect_migration(&database, &resolver).unwrap();
    migration.migrate().await.unwrap();
    let store = PostgresStore::connect_runtime(&database, &resolver).unwrap();
    store
        .register_source_generation(SOURCE_ID, GENERATION)
        .await
        .expect("register source generation");

    let administrator = actor("administrator", CaseworkRole::Administrator);
    let staff = actor("staff", CaseworkRole::Staff);
    let supervisor = actor("supervisor", CaseworkRole::Supervisor);
    let outsider = actor("outsider", CaseworkRole::Staff);
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".into(),
                staff: vec![
                    staff.principal.clone(),
                    actor("other-staff", CaseworkRole::Staff).principal,
                ],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: QUEUE.into(),
            },
            "bootstrap",
        )
        .await
        .unwrap();
    let service = CaseworkService::new(
        store,
        project(inbox),
        [Arc::new(source) as Arc<dyn SourceAdapter>],
    )
    .unwrap();
    let database = {
        let url = std::env::var(DATABASE_ENV).expect("visibility database URL");
        let (client, connection) = tokio_postgres::connect(&url, NoTls)
            .await
            .expect("connect visibility database");
        tokio::spawn(async move { connection.await.expect("visibility database connection") });
        client
    };
    Fixture {
        service,
        database,
        staff,
        supervisor,
        outsider,
    }
}

fn project(inbox: InboxPolicy) -> CaseworkProject {
    CaseworkProject {
        task_templates: Vec::new(),
        api_version: CASEWORK_API_VERSION.into(),
        kind: CASEWORK_KIND.into(),
        casework: CaseworkIdentity {
            id: "visibility-tests".into(),
            version: "1".into(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
        ],
        queues: vec![QueuePolicy {
            id: QUEUE.into(),
            label: "Default".into(),
        }],
        sources: vec![SourcePolicy {
            id: SOURCE_ID.into(),
            adapter: "mock".into(),
            description: "Test source".into(),
            requests: vec![SourceRequestPolicy {
                display_reference: None,
                entity: ENTITY.into(),
                queue: QUEUE.into(),
                projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }],
        hosted_kinds: Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox,
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.into(),
        principal_claim: "sub".into(),
        required_scopes: vec!["casework".into()],
        role,
        kinds: Vec::new(),
    }
}

fn actor(subject: &str, role: CaseworkRole) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://issuer.example".into(),
            subject: subject.into(),
        },
        profile_id: subject.into(),
        role,
    }
}

fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".into(),
        version: "1".into(),
        integrity: None,
        generation: GENERATION.into(),
    }
}

fn advanced_action_binding() -> SourceBinding {
    SourceBinding {
        source_revision: "2".into(),
        version: "2".into(),
        integrity: Some("sha256:action-result".into()),
        generation: GENERATION.into(),
    }
}

async fn add_item(
    service: &CaseworkService,
    id: Uuid,
    passive_target_seconds: Option<i64>,
) -> Uuid {
    service
        .store()
        .apply_observation(
            &AuthoritativeObservation {
                display_reference: None,
                submitted_at: None,
                stage_entered_at: None,
                review_timing: None,
                routing_context: None,
                subject: SubjectRef {
                    source_id: SOURCE_ID.into(),
                    kind: ENTITY.into(),
                    id: id.to_string(),
                },
                occurrence_key: "review:1".into(),
                ordered_revision: 1,
                binding: binding(),
                representation_etag: "\"request-1\"".into(),
                occurrence_kind: OccurrenceKind::Review,
                stage: Some("review".into()),
                state: OccurrenceState::Open,
                remaining_actions: Vec::new(),
            },
            QUEUE,
            passive_target_seconds,
        )
        .await
        .unwrap()
        .expect("open observation creates a work item")
        .item_id
}

async fn complete_item(service: &CaseworkService, id: Uuid) {
    let mut completed_binding = binding();
    completed_binding.source_revision = "2".into();
    service
        .store()
        .apply_observation(
            &AuthoritativeObservation {
                display_reference: None,
                submitted_at: None,
                stage_entered_at: None,
                review_timing: None,
                routing_context: None,
                subject: SubjectRef {
                    source_id: SOURCE_ID.into(),
                    kind: ENTITY.into(),
                    id: id.to_string(),
                },
                occurrence_key: "review:1".into(),
                ordered_revision: 2,
                binding: completed_binding,
                representation_etag: "\"request-2\"".into(),
                occurrence_kind: OccurrenceKind::Review,
                stage: Some("review".into()),
                state: OccurrenceState::Completed,
                remaining_actions: Vec::new(),
            },
            QUEUE,
            Some(1),
        )
        .await
        .unwrap();
}

fn policy(maximum_source_reads: usize, deadline_ms: u64) -> InboxPolicy {
    InboxPolicy {
        default_page_size: 10,
        maximum_candidate_scan: 10,
        maximum_source_reads,
        maximum_concurrent_source_reads: 2,
        page_deadline_milliseconds: deadline_ms,
    }
}

#[tokio::test]
async fn service_visibility_boundaries() {
    let _database = DATABASE.lock().await;
    zero_local_candidates_distinguish_empty_source_from_outage().await;
    warm_empty_source_status_does_not_mask_a_later_outage().await;
    incomplete_multipage_discovery_stays_incomplete_across_requests().await;
    reconciliation_resumes_remote_and_local_progress_after_restart().await;
    completed_discovery_waits_for_the_pending_tail_before_restarting().await;
    expired_remote_lease_fences_the_stale_page().await;
    expired_remote_lease_fences_the_stale_failure().await;
    generation_change_fences_the_stale_discovery_page().await;
    incomplete_reconciliation_preserves_outage_until_complete().await;
    sparse_disclosure_and_cursor_preserve_unvisited_candidates().await;
    next_item_returns_a_resumable_budget_page().await;
    exhausted_final_concealed_candidate_is_complete().await;
    caller_reads_use_bounded_order_preserving_concurrency().await;
    next_item_does_not_wait_for_a_speculative_tail_read().await;
    current_directory_controls_queue_visibility().await;
    source_deadline_is_hard_and_retryable().await;
    local_terminal_repair_survives_discovery_outage().await;
    periodic_reconciliation_refreshes_same_revision_actionability().await;
    request_correction_copy_is_persisted_then_filtered_for_the_caller().await;
    post_write_source_failure_retains_the_attempt_reference().await;
    definitive_refusal_during_recovery_releases_the_attempt_fence().await;
    inbox_views_filter_before_candidate_pagination().await;
    source_claim_requires_a_current_permitted_operation().await;
    full_source_binding_movement_fences_stale_items_and_claims().await;
    supervisor_release_and_holder_timing_obey_current_authority().await;
    exact_subject_selector_is_complete_and_cursor_bound().await;
}

async fn reconciliation_resumes_remote_and_local_progress_after_restart() {
    let total = 10_001;
    let (source, first_cursors) = MockSource::with_large_discovery(total);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        10_000
    );
    assert_eq!(first_cursors.lock().expect("first cursor lock").len(), 100);
    let local_progress = fixture.database.query_one(
        "SELECT local_after_kind,local_after_id,local_cycle_complete FROM casework_source_reconciliation_progress WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("first local continuation");
    assert!(local_progress.get::<_, Option<String>>(0).is_some());
    assert!(local_progress.get::<_, Option<String>>(1).is_some());
    assert!(!local_progress.get::<_, bool>(2));

    let (restarted_source, restarted_cursors) = MockSource::with_large_discovery(total);
    let restarted = CaseworkService::new(
        fixture.service.store().clone(),
        project(policy(10, 1_000)),
        [Arc::new(restarted_source) as Arc<dyn SourceAdapter>],
    )
    .expect("restart service from persisted progress");
    assert_eq!(restarted.reconcile_source(SOURCE_ID).await.unwrap(), 1);
    assert_eq!(
        restarted_cursors
            .lock()
            .expect("restart cursor lock")
            .first()
            .cloned()
            .flatten()
            .as_deref(),
        Some("10000")
    );
    let count: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_subjects WHERE source_id=$1 AND binding_generation=$2",
            &[&SOURCE_ID, &GENERATION],
        )
        .await
        .expect("count reconciled subjects")
        .get(0);
    assert_eq!(count, i64::try_from(total).unwrap());
    let local_complete: bool = fixture.database.query_one(
        "SELECT local_cycle_complete FROM casework_source_reconciliation_progress WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("completed local continuation").get(0);
    assert!(local_complete);
}

async fn completed_discovery_waits_for_the_pending_tail_before_restarting() {
    let total = 201;
    let (source, cursors) = MockSource::with_large_discovery(total);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        total
    );
    assert_eq!(cursors.lock().expect("discovery cursors").len(), 3);
    fixture.service.reconcile_source(SOURCE_ID).await.unwrap();
    fixture.service.reconcile_source(SOURCE_ID).await.unwrap();

    let tail_id = Uuid::from_u128(u128::try_from(total).unwrap()).to_string();
    let tail_applied: i64 = fixture.database.query_one(
        "SELECT applied_revision FROM casework_subjects WHERE source_id=$1 AND subject_kind=$2 AND subject_id=$3",
        &[&SOURCE_ID, &ENTITY, &tail_id],
    ).await.expect("tail subject").get(0);
    assert_eq!(tail_applied, 1);
    assert_eq!(
        fixture
            .service
            .store()
            .source_status(SOURCE_ID, GENERATION)
            .await
            .expect("source status"),
        Some((true, false))
    );
    assert_eq!(
        cursors.lock().expect("no restarted discovery").len(),
        3,
        "a completed cycle must not restart while its pending tail is draining"
    );
}

async fn expired_remote_lease_fences_the_stale_page() {
    let stale_id = Uuid::from_u128(210);
    let (source, gate) = MockSource::with_blocked_first_discovery(stale_id, false);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    let first_service = fixture.service.clone();
    let first = tokio::spawn(async move { first_service.reconcile_source(SOURCE_ID).await });
    gate.entered.notified().await;
    fixture.database.execute(
        "UPDATE casework_source_reconciliation_progress SET remote_lease_until=now()-interval '1 second' WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("expire first remote lease");

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );
    gate.release.notify_one();
    assert_eq!(first.await.expect("first reconciliation task").unwrap(), 0);
    let stale_exists: bool = fixture
        .database
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_subjects WHERE source_id=$1 AND subject_id=$2)",
            &[&SOURCE_ID, &stale_id.to_string()],
        )
        .await
        .expect("stale page subject check")
        .get(0);
    assert!(!stale_exists);
    assert_eq!(
        fixture
            .service
            .store()
            .source_status(SOURCE_ID, GENERATION)
            .await
            .unwrap(),
        Some((true, false))
    );
}

async fn expired_remote_lease_fences_the_stale_failure() {
    let (source, gate) = MockSource::with_blocked_first_discovery(Uuid::from_u128(211), true);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    let first_service = fixture.service.clone();
    let first = tokio::spawn(async move { first_service.reconcile_source(SOURCE_ID).await });
    gate.entered.notified().await;
    fixture.database.execute(
        "UPDATE casework_source_reconciliation_progress SET remote_lease_until=now()-interval '1 second' WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("expire first remote lease");

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );
    gate.release.notify_one();
    assert!(matches!(
        first.await.expect("first reconciliation task"),
        Err(ServiceError::Adapter(SourceAdapterError::Unavailable))
    ));
    assert_eq!(
        fixture
            .service
            .store()
            .source_status(SOURCE_ID, GENERATION)
            .await
            .expect("source status after stale failure"),
        Some((true, false))
    );
}

async fn generation_change_fences_the_stale_discovery_page() {
    let stale_id = Uuid::from_u128(221);
    let (source, gate) = MockSource::with_blocked_first_discovery(stale_id, false);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    let first_service = fixture.service.clone();
    let first = tokio::spawn(async move { first_service.reconcile_source(SOURCE_ID).await });
    gate.entered.notified().await;

    fixture
        .service
        .store()
        .register_source_generation(SOURCE_ID, "generation-2")
        .await
        .expect("register replacement generation");
    let replacement_source = MockSource::with_reads([]).with_generation("generation-2");
    let replacement_cursors = Arc::clone(&replacement_source.discovery_cursors);
    let replacement = CaseworkService::new(
        fixture.service.store().clone(),
        project(policy(10, 1_000)),
        [Arc::new(replacement_source) as Arc<dyn SourceAdapter>],
    )
    .expect("replacement generation service");
    assert_eq!(replacement.reconcile_source(SOURCE_ID).await.unwrap(), 0);
    gate.release.notify_one();
    assert!(matches!(
        first.await.expect("stale generation task"),
        Err(ServiceError::Store(StoreError::StaleGeneration))
    ));
    assert_eq!(
        replacement_cursors
            .lock()
            .expect("replacement cursor lock")
            .as_slice(),
        &[None]
    );
    let stale_exists: bool = fixture
        .database
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM casework_subjects WHERE source_id=$1 AND subject_id=$2)",
            &[&SOURCE_ID, &stale_id.to_string()],
        )
        .await
        .expect("stale subject check")
        .get(0);
    assert!(!stale_exists);
    let generations: Vec<String> = fixture.database.query(
        "SELECT binding_generation FROM casework_source_reconciliation_progress WHERE source_id=$1 ORDER BY binding_generation",
        &[&SOURCE_ID],
    ).await.expect("generation progress rows").into_iter().map(|row| row.get(0)).collect();
    assert_eq!(generations, ["generation-2"]);
    assert_eq!(
        replacement
            .store()
            .source_status(SOURCE_ID, "generation-2")
            .await
            .unwrap(),
        Some((true, false))
    );
}

async fn incomplete_reconciliation_preserves_outage_until_complete() {
    let fixture = fixture([], policy(10, 1_000)).await;
    let lease = Uuid::new_v4();
    fixture.database.execute(
        "UPDATE casework_source_reconciliation_progress SET remote_cycle_complete=false,remote_lease_token=$3,remote_lease_until=now()+interval '1 hour',local_cycle_complete=true WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION, &lease],
    ).await.expect("hold incomplete remote phase");
    fixture.database.execute(
        "INSERT INTO casework_source_status(source_id,binding_generation,remote_complete,unavailable,checked_at) VALUES($1,$2,false,true,now()) ON CONFLICT(source_id) DO UPDATE SET binding_generation=EXCLUDED.binding_generation,remote_complete=false,unavailable=true,checked_at=EXCLUDED.checked_at",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("record source outage");

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );
    assert_eq!(
        fixture
            .service
            .store()
            .source_status(SOURCE_ID, GENERATION)
            .await
            .unwrap(),
        Some((false, true))
    );

    fixture.database.execute(
        "UPDATE casework_source_reconciliation_progress SET remote_lease_token=NULL,remote_lease_until=NULL WHERE source_id=$1 AND binding_generation=$2",
        &[&SOURCE_ID, &GENERATION],
    ).await.expect("release incomplete remote phase");
    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );
    assert_eq!(
        fixture
            .service
            .store()
            .source_status(SOURCE_ID, GENERATION)
            .await
            .unwrap(),
        Some((true, false))
    );
}

async fn next_item_returns_a_resumable_budget_page() {
    let concealed = Uuid::from_u128(101);
    let visible = Uuid::from_u128(102);
    let fixture = fixture(
        [
            (concealed, CallerRead::Concealed),
            (visible, CallerRead::Visible("resumed")),
        ],
        policy(1, 1_000),
    )
    .await;
    add_item(&fixture.service, concealed, Some(1)).await;
    add_item(&fixture.service, visible, Some(3_600)).await;

    let first = fixture
        .service
        .next_item(&fixture.staff, "reader", "token", None, None)
        .await
        .expect("budget exhaustion is a page result");
    assert!(first.items.is_empty());
    assert_eq!(first.status, PageStatus::BudgetExhausted);
    let cursor = first.next_cursor.expect("budget page continuation");

    let resumed = fixture
        .service
        .next_item(&fixture.staff, "reader", "token", None, Some(&cursor))
        .await
        .expect("resume next-item scan");
    assert_eq!(resumed.items.len(), 1);
    assert_eq!(resumed.items[0].subject.id, visible.to_string());
}

async fn exhausted_final_concealed_candidate_is_complete() {
    let concealed = Uuid::from_u128(103);
    let fixture = fixture([(concealed, CallerRead::Concealed)], policy(1, 1_000)).await;
    fixture
        .service
        .reconcile_source(SOURCE_ID)
        .await
        .expect("complete source discovery");
    add_item(&fixture.service, concealed, Some(1)).await;

    let page = fixture
        .service
        .next_item(&fixture.staff, "reader", "token", None, None)
        .await
        .expect("fully examined next-item page");
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::Complete);
    assert!(page.next_cursor.is_none());
}

async fn caller_reads_use_bounded_order_preserving_concurrency() {
    let ids = [
        Uuid::from_u128(111),
        Uuid::from_u128(112),
        Uuid::from_u128(113),
    ];
    let source =
        MockSource::with_reads(ids.map(|id| (id, CallerRead::Delayed(Duration::from_millis(50)))));
    let peak = Arc::clone(&source.peak_caller_reads);
    let fixture = fixture_with_source(source, policy(3, 1_000)).await;
    for (index, id) in ids.into_iter().enumerate() {
        add_item(
            &fixture.service,
            id,
            Some(i64::try_from(index + 1).unwrap()),
        )
        .await;
    }

    let page = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 3, None, None)
        .await
        .expect("concurrent source page");
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(
        page.items
            .iter()
            .map(|item| item.subject.id.as_str())
            .collect::<Vec<_>>(),
        ids.iter().map(Uuid::to_string).collect::<Vec<_>>()
    );
}

async fn next_item_does_not_wait_for_a_speculative_tail_read() {
    let first = Uuid::from_u128(121);
    let slow_tail = Uuid::from_u128(122);
    let fixture = fixture(
        [
            (first, CallerRead::Visible("first")),
            (slow_tail, CallerRead::Delayed(Duration::from_secs(5))),
        ],
        policy(2, 1_000),
    )
    .await;
    add_item(&fixture.service, first, Some(1)).await;
    add_item(&fixture.service, slow_tail, Some(3_600)).await;

    let started = Instant::now();
    let page = fixture
        .service
        .next_item(&fixture.staff, "reader", "token", None, None)
        .await
        .expect("first visible item");
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].subject.id, first.to_string());
}

async fn source_claim_requires_a_current_permitted_operation() {
    let subject_id = Uuid::from_u128(34);
    let fixture = fixture(
        [(subject_id, CallerRead::Visible("previous reviewer"))],
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .expect("local candidate")
        .items
        .pop()
        .expect("source item");
    let (visible, source) = fixture
        .service
        .caller_item(&fixture.staff, item.item_id, "reader", "token")
        .await
        .expect("previous reviewer can still read the item");
    assert!(source.permitted_operations.is_empty());
    assert!(!visible
        .actions
        .iter()
        .any(|action| action.operation == "claim"));
    assert!(matches!(
        fixture
            .service
            .claim_source_item(
                &fixture.staff,
                item.item_id,
                item.revision,
                "reader",
                "excluded-reviewer-claim",
                "token",
            )
            .await,
        Err(ServiceError::Forbidden)
    ));

    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "existing-holder",
        )
        .await
        .expect("establish an existing holder without changing source authority");
    fixture
        .service
        .release_source_item(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            "excluded-reviewer-release",
            "token",
        )
        .await
        .expect("an existing holder can still release work");
}

async fn full_source_binding_movement_fences_stale_items_and_claims() {
    let subject_id = Uuid::from_u128(35);
    let fixture = fixture(
        [(subject_id, CallerRead::Visible("current reader"))],
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .expect("local candidate")
        .items
        .pop()
        .expect("source item");

    for (token, idempotency_key) in [
        ("moved-binding-revision", "stale-revision-claim"),
        ("moved-binding-version", "stale-version-claim"),
        ("moved-binding-integrity", "stale-integrity-claim"),
    ] {
        assert!(matches!(
            fixture
                .service
                .caller_item(&fixture.staff, item.item_id, "reader", token)
                .await,
            Err(ServiceError::BindingMoved)
        ));
        assert!(matches!(
            fixture
                .service
                .claim_source_item(
                    &fixture.staff,
                    item.item_id,
                    item.revision,
                    "reader",
                    idempotency_key,
                    token,
                )
                .await,
            Err(ServiceError::BindingMoved)
        ));
    }
    assert!(fixture
        .service
        .store()
        .item(item.item_id)
        .await
        .expect("stale local item remains")
        .holder
        .is_none());
}

async fn exact_subject_selector_is_complete_and_cursor_bound() {
    let selected_id = Uuid::from_u128(32);
    let other_id = Uuid::from_u128(33);
    let fixture = fixture(
        [
            (selected_id, CallerRead::Visible("selected")),
            (other_id, CallerRead::Visible("other")),
        ],
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, selected_id, None).await;
    add_item(&fixture.service, other_id, None).await;

    let unfiltered = fixture
        .service
        .inbox_for_view(
            &fixture.staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            None,
            None,
            None,
        )
        .await
        .expect("unfiltered first page");
    let cursor = unfiltered.next_cursor.expect("unvisited item cursor");
    let selected = subject(selected_id);
    let page = fixture
        .service
        .inbox_for_view(
            &fixture.staff,
            "reader",
            "token",
            InboxView::MyTeams,
            10,
            None,
            Some(&selected),
            None,
        )
        .await
        .expect("exact subject page");
    assert_eq!(page.status, PageStatus::Complete);
    assert_eq!(page.served_queues, [QUEUE]);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].subject, selected);
    assert!(page.next_cursor.is_none());

    let missing = subject(Uuid::from_u128(34));
    let page = fixture
        .service
        .inbox_for_view(
            &fixture.staff,
            "reader",
            "token",
            InboxView::MyTeams,
            10,
            None,
            Some(&missing),
            None,
        )
        .await
        .expect("missing exact subject is an empty complete page");
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::Complete);
    assert_eq!(page.served_queues, [QUEUE]);
    assert!(matches!(
        fixture
            .service
            .inbox_for_view(
                &fixture.staff,
                "reader",
                "token",
                InboxView::MyTeams,
                10,
                None,
                Some(&selected),
                Some(&cursor),
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
}

async fn supervisor_release_and_holder_timing_obey_current_authority() {
    let released_subject = Uuid::from_u128(30);
    let fenced_subject = Uuid::from_u128(31);
    let mut source = MockSource::with_reads([
        (released_subject, CallerRead::Visible("released")),
        (fenced_subject, CallerRead::Visible("fenced")),
    ]);
    source
        .approve_reads
        .extend([released_subject.to_string(), fenced_subject.to_string()]);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, released_subject, None).await;
    add_item(&fixture.service, fenced_subject, None).await;
    let items = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 10, None, None)
        .await
        .expect("seeded items")
        .items;
    let released_item = items
        .iter()
        .find(|item| item.subject.id == released_subject.to_string())
        .expect("release item");
    let (open_for_supervisor, _) = fixture
        .service
        .caller_item(
            &fixture.supervisor,
            released_item.item_id,
            "reader",
            "token",
        )
        .await
        .expect("supervisor sees open source item");
    assert_eq!(open_for_supervisor.actions.len(), 1);
    assert_eq!(open_for_supervisor.actions[0].operation, "assign");
    let claimed = fixture
        .service
        .claim_source_item(
            &fixture.staff,
            released_item.item_id,
            released_item.revision,
            "reader",
            "claim-supervisor-release",
            "token",
        )
        .await
        .expect("staff claims source item");
    let held_since = claimed.held_since.expect("claim establishes heldSince");
    assert!(claimed
        .actions
        .iter()
        .any(|action| action.operation == "delegate"));
    fixture
        .service
        .save_source_draft(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            &claimed.binding,
            "reviewing",
            &[],
            "draft-held-since",
            "token",
        )
        .await
        .expect("unrelated draft revision");
    let (after_draft, _) = fixture
        .service
        .caller_item(&fixture.supervisor, claimed.item_id, "reader", "token")
        .await
        .expect("supervisor sees held item");
    assert_eq!(after_draft.held_since, Some(held_since));
    assert_eq!(
        after_draft
            .actions
            .iter()
            .map(|action| action.operation.as_str())
            .collect::<Vec<_>>(),
        ["assign", "release"]
    );
    let sibling_supervisor = actor("sibling-supervisor", CaseworkRole::Supervisor);
    assert!(matches!(
        fixture
            .service
            .caller_item(&sibling_supervisor, claimed.item_id, "reader", "token")
            .await,
        Err(ServiceError::NotFound)
    ));
    let released = fixture
        .service
        .release_source_item(
            &fixture.supervisor,
            claimed.item_id,
            after_draft.revision,
            "reader",
            "supervisor-release",
            "token",
        )
        .await
        .expect("supervisor releases another holder");
    assert_eq!(released.state, OccurrenceState::Open);
    assert!(released.holder.is_none());
    assert!(released.held_since.is_none());
    let release_replay = fixture
        .service
        .release_source_item(
            &fixture.supervisor,
            claimed.item_id,
            after_draft.revision,
            "reader",
            "supervisor-release",
            "token",
        )
        .await
        .expect("current supervisor replays exact release");
    assert_eq!(release_replay, released);
    let release_detail: serde_json::Value = fixture
        .database
        .query_one(
            "SELECT detail FROM casework_history WHERE item_id=$1 AND kind='released'",
            &[&claimed.item_id],
        )
        .await
        .expect("source release history")
        .get(0);
    assert_eq!(
        release_detail["previousHolder"]["subject"],
        fixture.staff.principal.subject
    );

    fixture
        .database
        .execute(
            "DELETE FROM casework_memberships WHERE team_id='team' AND issuer=$1 AND subject=$2 AND membership_kind='supervisor'",
            &[&fixture.supervisor.principal.issuer, &fixture.supervisor.principal.subject],
        )
        .await
        .expect("revoke supervisor membership");
    assert!(matches!(
        fixture
            .service
            .release_source_item(
                &fixture.supervisor,
                claimed.item_id,
                after_draft.revision,
                "reader",
                "supervisor-release",
                "token"
            )
            .await,
        Err(ServiceError::Store(StoreError::NotFound)) | Err(ServiceError::NotFound)
    ));
    fixture
        .database
        .execute(
            "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,$2,'supervisor')",
            &[&fixture.supervisor.principal.issuer, &fixture.supervisor.principal.subject],
        )
        .await
        .expect("restore supervisor membership");

    let fenced_item = items
        .iter()
        .find(|item| item.subject.id == fenced_subject.to_string())
        .expect("fenced item");
    let fenced = fixture
        .service
        .claim_source_item(
            &fixture.staff,
            fenced_item.item_id,
            fenced_item.revision,
            "reader",
            "claim-fenced-release",
            "token",
        )
        .await
        .expect("claim fenced item");
    let prepared = PreparedSourceAttempt {
        source_binding: fenced.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(vec![2]).expect("bounded evidence"),
    };
    fixture
        .service
        .store()
        .reserve_attempt_for_execution(
            &fixture.staff,
            fenced.item_id,
            fenced.revision,
            "reader",
            OperationName::parse("approve").expect("operation"),
            None,
            &[],
            "fenced-release-attempt",
            "sha256:fenced-release",
            &prepared,
        )
        .await
        .expect("reserve live attempt");
    let (visible, _) = fixture
        .service
        .caller_item(&fixture.supervisor, fenced.item_id, "reader", "token")
        .await
        .expect("supervisor may see fenced item");
    assert!(visible.actions.is_empty());
    assert!(matches!(
        fixture
            .service
            .release_source_item(
                &fixture.supervisor,
                fenced.item_id,
                fenced.revision,
                "reader",
                "release-live-attempt",
                "token"
            )
            .await,
        Err(ServiceError::Store(
            StoreError::AttemptPending | StoreError::Conflict
        ))
    ));
}

async fn post_write_source_failure_retains_the_attempt_reference() {
    let subject_id = Uuid::from_u128(29);
    let (source, execute_calls) = MockSource::with_post_write_read_failure(subject_id);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-post-write",
        )
        .await
        .unwrap();
    let error = fixture
        .service
        .decide_mutation(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            &claimed.binding,
            "post-write-failure",
            "token",
        )
        .await
        .expect_err("post-write caller read fails");
    let attempt_id = match error {
        ServiceError::PostWriteSourceUnavailable(attempt_id) => attempt_id,
        other => panic!("unexpected post-write error: {other:?}"),
    };
    let (_, stored) = fixture
        .service
        .store()
        .terminal_attempt_by_key(&fixture.staff, claimed.item_id, "post-write-failure")
        .await
        .unwrap()
        .expect("durable terminal attempt");
    assert_eq!(attempt_id, stored.attempt_id);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
}

async fn definitive_refusal_during_recovery_releases_the_attempt_fence() {
    for (subject_id, recover_by_key) in [(Uuid::from_u128(25), false), (Uuid::from_u128(26), true)]
    {
        let (source, execute_calls) = MockSource::with_recovery_definitive_refusal(
            subject_id,
            CallerRead::Visible("authorized"),
        );
        let fixture = fixture_with_source(source, policy(10, 1_000)).await;
        add_item(&fixture.service, subject_id, Some(1)).await;
        let item = fixture
            .service
            .store()
            .inbox_candidates(&fixture.staff, 1, None, None)
            .await
            .unwrap()
            .items
            .pop()
            .unwrap();
        let claimed = fixture
            .service
            .store()
            .claim(
                &fixture.staff,
                item.item_id,
                item.revision,
                "claim-recovery-refusal",
            )
            .await
            .unwrap();
        let decision = fixture
            .service
            .decide(
                &fixture.staff,
                claimed.item_id,
                claimed.revision,
                "reader",
                OperationName::parse("approve").expect("approve operation"),
                None,
                &[],
                &claimed.binding,
                "recovery-refusal-key",
                "token",
            )
            .await;
        let attempt_id = match decision {
            Err(ServiceError::UncertainAttempt(attempt_id)) => attempt_id,
            other => panic!("first execution must remain recoverable: {other:?}"),
        };
        assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let recovery = if recover_by_key {
            fixture
                .service
                .recover_by_key(
                    &fixture.staff,
                    claimed.item_id,
                    "reader",
                    "recovery-refusal-key",
                    "token",
                )
                .await
        } else {
            fixture
                .service
                .recover(
                    &fixture.staff,
                    claimed.item_id,
                    attempt_id,
                    "reader",
                    "token",
                )
                .await
        };
        assert!(
            matches!(
                recovery,
                Err(ServiceError::Adapter(SourceAdapterError::ActionNotOffered))
            ),
            "{recovery:?}"
        );
        assert_eq!(execute_calls.load(Ordering::SeqCst), 2);

        let restored = fixture.service.store().item(claimed.item_id).await.unwrap();
        assert_eq!(restored.state, OccurrenceState::Claimed);
        assert_eq!(restored.holder, claimed.holder);
        assert!(fixture
            .service
            .store()
            .live_attempt_for_actor(&fixture.staff, claimed.item_id, "reader")
            .await
            .unwrap()
            .is_none());

        let replay = if recover_by_key {
            fixture
                .service
                .recover_by_key(
                    &fixture.staff,
                    claimed.item_id,
                    "reader",
                    "recovery-refusal-key",
                    "token",
                )
                .await
        } else {
            fixture
                .service
                .recover(
                    &fixture.staff,
                    claimed.item_id,
                    attempt_id,
                    "reader",
                    "token",
                )
                .await
        }
        .expect("refused attempt replays without another source execution");
        assert_eq!(
            replay.0.state,
            registry_casework_core::AttemptState::Refused
        );
        assert!(replay.1.is_none());
        assert_eq!(execute_calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn caller_owned_live_attempt_survives_a_fresh_session_without_cross_actor_disclosure() {
    let _database = DATABASE.lock().await;
    let subject_id = Uuid::from_u128(24);
    let source = MockSource::with_reads([(subject_id, CallerRead::Visible("authorized"))]);
    let execute_calls = Arc::clone(&source.execute_calls);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-live-attempt",
        )
        .await
        .unwrap();
    let prepared = PreparedSourceAttempt {
        source_binding: claimed.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(vec![1]).unwrap(),
    };
    let (reserved, execution_token) = fixture
        .service
        .store()
        .reserve_attempt_for_execution(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("approve").expect("approve operation"),
            Some("bounded reason"),
            &[],
            "live-attempt-key",
            "sha256:live-attempt-request",
            &prepared,
        )
        .await
        .unwrap();
    let uncertain = fixture
        .service
        .store()
        .mark_attempt_uncertain(&fixture.staff, reserved.attempt_id, execution_token)
        .await
        .unwrap();

    let fresh_session_actor = fixture.staff.clone();
    let (visible, _) = fixture
        .service
        .caller_item(
            &fresh_session_actor,
            claimed.item_id,
            "reader",
            "fresh-session-token",
        )
        .await
        .unwrap();
    assert_eq!(visible.live_attempt, Some(uncertain.clone()));
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);

    let (moved_generation, _) = fixture
        .service
        .caller_item(
            &fresh_session_actor,
            claimed.item_id,
            "reader",
            "moved-generation-token",
        )
        .await
        .unwrap();
    assert_eq!(moved_generation.live_attempt, Some(uncertain.clone()));
    assert!(moved_generation.actions.is_empty());

    for token in [
        "moved-binding-revision",
        "moved-binding-version",
        "moved-binding-integrity",
    ] {
        let (moved_binding, _) = fixture
            .service
            .caller_item(&fresh_session_actor, claimed.item_id, "reader", token)
            .await
            .unwrap();
        assert_eq!(moved_binding.live_attempt, Some(uncertain.clone()));
        assert!(moved_binding.actions.is_empty());
    }

    let (other_actor_view, _) = fixture
        .service
        .caller_item(
            &actor("other-staff", CaseworkRole::Staff),
            claimed.item_id,
            "reader",
            "other-token",
        )
        .await
        .unwrap();
    assert!(other_actor_view.live_attempt.is_none());

    let mut other_profile = fixture.staff.clone();
    other_profile.profile_id = "other-casework-profile".into();
    let (other_profile_view, _) = fixture
        .service
        .caller_item(
            &other_profile,
            claimed.item_id,
            "reader",
            "other-profile-token",
        )
        .await
        .unwrap();
    assert!(other_profile_view.live_attempt.is_none());

    let (other_source_profile_view, _) = fixture
        .service
        .caller_item(
            &fixture.staff,
            claimed.item_id,
            "other-reader",
            "other-source-profile-token",
        )
        .await
        .unwrap();
    assert!(other_source_profile_view.live_attempt.is_none());

    let concealed = fixture
        .service
        .caller_item(&fixture.staff, claimed.item_id, "reader", "concealed-token")
        .await;
    assert!(matches!(
        concealed,
        Err(ServiceError::Adapter(SourceAdapterError::Concealed))
    ));
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
}

async fn inbox_views_filter_before_candidate_pagination() {
    let unclaimed = Uuid::from_u128(20);
    let mine = Uuid::from_u128(21);
    let (source, _, _) = MockSource::with_successful_action(mine, CallerRead::Visible("mine"));
    let mut source = source;
    source.reads.insert(
        unclaimed.to_string(),
        CallerRead::Visible("unclaimed-before-mine"),
    );
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, unclaimed, None).await;
    add_item(&fixture.service, mine, None).await;
    let mine_item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 10, None, None)
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|item| item.subject.id == mine.to_string())
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            mine_item.item_id,
            mine_item.revision,
            "claim-mine",
        )
        .await
        .unwrap();

    let mine_page = fixture
        .service
        .inbox_for_view(
            &fixture.staff,
            "reader",
            "token",
            registry_casework_core::InboxView::Mine,
            1,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(mine_page.items.len(), 1);
    assert_eq!(mine_page.items[0].item_id, claimed.item_id);

    fixture
        .service
        .decide(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            &claimed.binding,
            "complete-mine",
            "token",
        )
        .await
        .unwrap();
    complete_item(&fixture.service, mine).await;
    let completed = fixture
        .service
        .inbox_for_view(
            &fixture.staff,
            "reader",
            "advanced-terminal-binding",
            registry_casework_core::InboxView::CompletedByMe,
            1,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(completed.items.len(), 1);
    assert_eq!(completed.items[0].item_id, claimed.item_id);
    assert_eq!(completed.items[0].binding.source_revision, "2");
    assert!(completed.items[0].actions.is_empty());

    assert!(matches!(
        fixture
            .service
            .inbox_for_view(
                &fixture.staff,
                "reader",
                "moved-generation-token",
                registry_casework_core::InboxView::CompletedByMe,
                1,
                None,
                None,
                None,
            )
            .await,
        Err(ServiceError::BindingMoved)
    ));
}

#[tokio::test]
async fn recovery_problem_discloses_only_the_entitled_original_attempt() {
    let _database = DATABASE.lock().await;
    let subject_id = Uuid::from_u128(22);
    let mut source = MockSource::with_reads([(subject_id, CallerRead::Visible("authorized"))]);
    source.approve_reads.insert(subject_id.to_string());
    let prepare_calls = Arc::clone(&source.prepare_calls);
    let execute_calls = Arc::clone(&source.execute_calls);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-uncertain",
        )
        .await
        .unwrap();
    let configured_project = project(policy(10, 1_000));
    let app = router(HttpState {
        service: fixture.service.clone(),
        authenticator: Arc::new(authenticator(&configured_project)),
        project: Arc::new(configured_project),
    });
    let decision_path = format!("/v1/work-items/{}/decisions", claimed.item_id);
    let decision_body = json!({
        "displayedBinding": claimed.binding,
        "sourceProfileId": "reader",
        "operation": "approve"
    });
    let decision_headers = [
        (SOURCE_PROFILE_HEADER, "reader"),
        (IF_MATCH_HEADER, "\"2\""),
        (IDEMPOTENCY_KEY_HEADER, "uncertain-decision"),
    ];
    let response = app
        .clone()
        .oneshot(authenticated_request(
            "POST",
            &decision_path,
            &access_token("staff"),
            "staff",
            decision_body.clone(),
            &decision_headers,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let attempt_id = response
        .headers()
        .get(ATTEMPT_REFERENCE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("entitled uncertainty carries the original attempt UUID");
    let problem = response_body(response).await;
    assert_eq!(problem["code"], "work-item.recovery-pending");
    assert_eq!(
        problem
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>(),
        HashSet::from([
            "type".into(),
            "title".into(),
            "status".into(),
            "detail".into(),
            "code".into(),
            "traceId".into(),
        ])
    );
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let wrong_actor = app
        .clone()
        .oneshot(authenticated_request(
            "POST",
            &decision_path,
            &access_token("other-staff"),
            "staff",
            decision_body.clone(),
            &decision_headers,
        ))
        .await
        .unwrap();
    assert_eq!(wrong_actor.status(), StatusCode::CONFLICT);
    assert!(wrong_actor
        .headers()
        .get(ATTEMPT_REFERENCE_HEADER)
        .is_none());
    let wrong_problem = response_body(wrong_actor).await;
    assert_eq!(wrong_problem["code"], "idempotency.key-reused");
    assert!(!wrong_problem.to_string().contains(&attempt_id.to_string()));
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let wrong_source_profile = app
        .clone()
        .oneshot(authenticated_request(
            "POST",
            &decision_path,
            &access_token("staff"),
            "staff",
            json!({
                "displayedBinding": claimed.binding,
                "sourceProfileId": "other-reader",
                "operation": "approve"
            }),
            &[
                (SOURCE_PROFILE_HEADER, "other-reader"),
                (IF_MATCH_HEADER, "\"4\""),
                (IDEMPOTENCY_KEY_HEADER, "wrong-source-profile"),
            ],
        ))
        .await
        .unwrap();
    let wrong_source_status = wrong_source_profile.status();
    assert!(wrong_source_profile
        .headers()
        .get(ATTEMPT_REFERENCE_HEADER)
        .is_none());
    let wrong_source_problem = response_body(wrong_source_profile).await;
    assert_eq!(
        wrong_source_status,
        StatusCode::FORBIDDEN,
        "{wrong_source_problem}"
    );
    assert!(!wrong_source_problem
        .to_string()
        .contains(&attempt_id.to_string()));
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let recovery_path = format!(
        "/v1/work-items/{}/attempts/{attempt_id}/recover",
        claimed.item_id
    );
    let active_lease = fixture
        .service
        .store()
        .acquire_recovery_execution(&fixture.staff, attempt_id)
        .await
        .unwrap();
    let in_progress = app
        .clone()
        .oneshot(authenticated_request(
            "POST",
            &recovery_path,
            &access_token("staff"),
            "staff",
            json!({"sourceProfileId":"reader"}),
            &[(SOURCE_PROFILE_HEADER, "reader")],
        ))
        .await
        .unwrap();
    assert_eq!(in_progress.status(), StatusCode::CONFLICT);
    assert_eq!(
        in_progress.headers()[ATTEMPT_REFERENCE_HEADER],
        attempt_id.to_string()
    );
    assert_eq!(
        response_body(in_progress).await["code"],
        "work-item.recovery-pending"
    );
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
    fixture
        .service
        .store()
        .mark_attempt_uncertain(&fixture.staff, attempt_id, active_lease)
        .await
        .unwrap();

    let different_key = app
        .clone()
        .oneshot(authenticated_request(
            "POST",
            &decision_path,
            &access_token("staff"),
            "staff",
            decision_body,
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"3\""),
                (IDEMPOTENCY_KEY_HEADER, "different-command-key"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(different_key.status(), StatusCode::CONFLICT);
    assert_eq!(
        different_key.headers()[ATTEMPT_REFERENCE_HEADER],
        attempt_id.to_string()
    );
    assert_eq!(
        response_body(different_key).await["code"],
        "work-item.recovery-pending"
    );
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let recovery = app
        .oneshot(authenticated_request(
            "POST",
            &recovery_path,
            &access_token("staff"),
            "staff",
            json!({"sourceProfileId":"reader"}),
            &[(SOURCE_PROFILE_HEADER, "reader")],
        ))
        .await
        .unwrap();
    assert_eq!(recovery.status(), StatusCode::OK);
    let recovered = response_body(recovery).await;
    assert_eq!(recovered["attempt"]["attemptId"], attempt_id.to_string());
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 2);
}

async fn assert_decision_refusal_problem(
    source_error: SourceAdapterError,
    expected_status: StatusCode,
    expected_code: &str,
    expected_detail: &str,
) {
    let subject_id = Uuid::from_u128(1_020);
    let fixture = fixture_with_source(
        MockSource::with_action_error(subject_id, source_error),
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, subject_id, None).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-source-refusal",
        )
        .await
        .unwrap();
    let configured_project = project(policy(10, 1_000));
    let app = router(HttpState {
        service: fixture.service.clone(),
        authenticator: Arc::new(authenticator(&configured_project)),
        project: Arc::new(configured_project),
    });
    let decision_path = format!("/v1/work-items/{}/decisions", claimed.item_id);
    let expected_revision = format!("\"{}\"", claimed.revision);
    let response = app
        .oneshot(authenticated_request(
            "POST",
            &decision_path,
            &access_token("staff"),
            "staff",
            json!({
                "displayedBinding": claimed.binding,
                "sourceProfileId": "reader",
                "operation": "approve"
            }),
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, expected_revision.as_str()),
                (IDEMPOTENCY_KEY_HEADER, "source-refusal"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), expected_status);
    let problem = response_body(response).await;
    assert_eq!(problem["code"], expected_code);
    assert_eq!(problem["detail"], expected_detail);
}

#[tokio::test]
async fn source_request_rejection_has_a_distinct_http_problem() {
    let _database = DATABASE.lock().await;
    assert_decision_refusal_problem(
        SourceAdapterError::RequestRejected,
        StatusCode::UNPROCESSABLE_ENTITY,
        "request.source-rejected",
        "The source refused the request body. Fix the request before trying again.",
    )
    .await;
}

#[tokio::test]
async fn missing_source_record_has_a_distinct_http_problem() {
    let _database = DATABASE.lock().await;
    assert_decision_refusal_problem(
        SourceAdapterError::RecordMissing,
        StatusCode::NOT_FOUND,
        "source.record-missing",
        "The bound source record is no longer at the registered location.",
    )
    .await;
}

#[tokio::test]
async fn refused_reviewer_binding_has_a_distinct_http_problem() {
    let _database = DATABASE.lock().await;
    assert_decision_refusal_problem(
        SourceAdapterError::ReviewerNotAuthorized,
        StatusCode::FORBIDDEN,
        "source.reviewer-not-authorized",
        "The source refused the reviewer binding. Check the selected source profile and credential.",
    )
    .await;
}

#[tokio::test]
async fn stale_source_action_remains_not_offered() {
    let _database = DATABASE.lock().await;
    assert_decision_refusal_problem(
        SourceAdapterError::ActionNotOffered,
        StatusCode::CONFLICT,
        "work-item.not-offered",
        "The registry did not offer this action to you. Refresh to check again.",
    )
    .await;
}

async fn zero_local_candidates_distinguish_empty_source_from_outage() {
    let empty = fixture([], policy(10, 1_000)).await;
    let page = empty
        .service
        .inbox(&empty.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::Complete);

    let outage =
        fixture_with_source(MockSource::with_unavailable_discovery(), policy(10, 1_000)).await;
    let page = outage
        .service
        .inbox(&outage.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::SourceUnavailable);
}

async fn warm_empty_source_status_does_not_mask_a_later_outage() {
    let (source, unavailable) = MockSource::with_discovery_control();
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    let warm = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(warm.items.is_empty());
    assert_eq!(warm.status, PageStatus::Complete);
    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );

    unavailable.store(true, Ordering::SeqCst);
    let degraded = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(degraded.items.is_empty());
    assert_eq!(degraded.status, PageStatus::SourceUnavailable);
}

async fn incomplete_multipage_discovery_stays_incomplete_across_requests() {
    let first = Uuid::from_u128(8);
    let second = Uuid::from_u128(9);
    let fixture = fixture_with_source(
        MockSource::with_multipage_discovery(first, second),
        policy(10, 1_000),
    )
    .await;

    let first_probe = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, None)
        .await
        .unwrap();
    assert!(first_probe.items.is_empty());
    assert_eq!(first_probe.status, PageStatus::BudgetExhausted);
    assert!(first_probe.next_cursor.is_some());
    assert_eq!(fixture.service.synchronize_pending(100).await.unwrap(), 1);

    let concealed_first = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, None)
        .await
        .unwrap();
    assert!(concealed_first.items.is_empty());
    assert_eq!(concealed_first.status, PageStatus::BudgetExhausted);
    assert!(concealed_first.next_cursor.is_some());

    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        2
    );
    let complete = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, None)
        .await
        .unwrap();
    assert_eq!(complete.items.len(), 1);
    assert_eq!(complete.items[0].subject.id, second.to_string());
    assert_eq!(complete.status, PageStatus::Complete);
}

async fn sparse_disclosure_and_cursor_preserve_unvisited_candidates() {
    let concealed = Uuid::from_u128(1);
    let visible = Uuid::from_u128(2);
    let fixture = fixture(
        [
            (concealed, CallerRead::Concealed),
            (visible, CallerRead::Visible(DISCLOSURE_CANARY)),
        ],
        policy(1, 1_000),
    )
    .await;
    add_item(&fixture.service, concealed, Some(1)).await;
    add_item(&fixture.service, visible, Some(3_600)).await;

    let first = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, None)
        .await
        .unwrap();
    assert!(first.items.is_empty());
    assert_eq!(first.status, PageStatus::BudgetExhausted);
    let cursor = first
        .next_cursor
        .as_deref()
        .expect("unvisited candidate cursor");
    assert_ne!(cursor, "1");
    complete_item(&fixture.service, concealed).await;

    let second = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, Some(cursor))
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].subject.id, visible.to_string());
    assert!(!serde_json::to_string(&second)
        .unwrap()
        .contains(DISCLOSURE_CANARY));
}

async fn source_deadline_is_hard_and_retryable() {
    let slow = Uuid::from_u128(3);
    let fixture = fixture(
        [(slow, CallerRead::Delayed(Duration::from_secs(5)))],
        policy(10, 100),
    )
    .await;
    add_item(&fixture.service, slow, Some(1)).await;

    let started = Instant::now();
    let page = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, None)
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(page.status, PageStatus::SourceUnavailable);
    assert!(page.items.is_empty());
    let cursor = page.next_cursor.expect("timeout remains retryable");
    let retry = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, None, Some(&cursor))
        .await
        .expect("cursor before the first examined item remains valid");
    assert_eq!(retry.status, PageStatus::SourceUnavailable);
    assert!(retry.items.is_empty());
}

#[tokio::test]
async fn source_outage_is_distinct_from_empty_inbox_and_holdings() {
    let _database = DATABASE.lock().await;
    let unavailable = Uuid::from_u128(4);
    let empty = fixture([], policy(10, 1_000)).await;
    let inbox = empty
        .service
        .inbox(&empty.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(inbox.items.is_empty());
    assert_eq!(inbox.status, PageStatus::Complete);
    let holdings = empty
        .service
        .caller_visible_holdings(&empty.supervisor, "reader", "token", 10, None)
        .await
        .unwrap();
    assert!(holdings.items.is_empty());
    assert_eq!(holdings.status, PageStatus::Complete);

    let visible = Uuid::from_u128(40);
    let concealed = Uuid::from_u128(41);
    let scoped = fixture(
        [
            (visible, CallerRead::Visible("visible holding")),
            (concealed, CallerRead::Concealed),
        ],
        policy(10, 1_000),
    )
    .await;
    let visible_item = add_item(&scoped.service, visible, Some(1)).await;
    let concealed_item = add_item(&scoped.service, concealed, Some(2)).await;
    scoped
        .service
        .store()
        .claim(&scoped.staff, visible_item, 1, "claim-visible")
        .await
        .unwrap();
    scoped
        .service
        .store()
        .claim(&scoped.staff, concealed_item, 1, "claim-concealed")
        .await
        .unwrap();
    scoped
        .service
        .store()
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .unwrap();
    let holdings = scoped
        .service
        .caller_visible_holdings(&scoped.supervisor, "reader", "token", 10, None)
        .await
        .unwrap();
    assert_eq!(holdings.status, PageStatus::Complete);
    assert_eq!(holdings.items.len(), 1);
    assert_eq!(holdings.items[0].active_items, 1);

    let first_visible = Uuid::from_u128(42);
    let outage = fixture(
        [
            (first_visible, CallerRead::Visible("visible before outage")),
            (unavailable, CallerRead::Unavailable),
        ],
        policy(10, 1_000),
    )
    .await;
    let first_visible_item = add_item(&outage.service, first_visible, Some(1)).await;
    let unavailable_item = add_item(&outage.service, unavailable, Some(3_600)).await;
    outage
        .service
        .store()
        .claim(&outage.staff, first_visible_item, 1, "claim-first-visible")
        .await
        .unwrap();
    outage
        .service
        .store()
        .claim(&outage.staff, unavailable_item, 1, "claim-unavailable")
        .await
        .unwrap();
    outage
        .service
        .store()
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .unwrap();
    let inbox = outage
        .service
        .inbox(&outage.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert_eq!(inbox.items.len(), 1);
    assert_eq!(inbox.items[0].subject.id, first_visible.to_string());
    assert_eq!(inbox.status, PageStatus::SourceUnavailable);
    let holdings = outage
        .service
        .caller_visible_holdings(&outage.supervisor, "reader", "token", 10, None)
        .await
        .unwrap();
    assert!(holdings.items.is_empty());
    assert_eq!(holdings.status, PageStatus::SourceUnavailable);
    let retry_cursor = holdings.next_cursor.expect("failed page is retryable");
    let retry = outage
        .service
        .caller_visible_holdings(
            &outage.supervisor,
            "reader",
            "token",
            1,
            Some(&retry_cursor),
        )
        .await
        .unwrap();
    assert_eq!(retry.items.len(), 1);
    assert_eq!(retry.items[0].active_items, 1);
    assert_eq!(retry.status, PageStatus::BudgetExhausted);
}

async fn current_directory_controls_queue_visibility() {
    let visible = Uuid::from_u128(5);
    let fixture = fixture(
        [(visible, CallerRead::Visible("visible"))],
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, visible, Some(1)).await;

    let member = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert_eq!(member.items.len(), 1);
    let outsider = fixture
        .service
        .inbox(&fixture.outsider, "reader", "token", 10, None, None)
        .await
        .unwrap();
    assert!(outsider.items.is_empty());
    assert_eq!(outsider.status, PageStatus::Complete);
}

async fn local_terminal_repair_survives_discovery_outage() {
    let terminal = Uuid::from_u128(7);
    let fixture = fixture_with_source(
        MockSource::with_unavailable_discovery_and_terminal_read(terminal),
        policy(10, 1_000),
    )
    .await;
    add_item(&fixture.service, terminal, Some(1)).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .expect("local item starts active");

    assert!(matches!(
        fixture.service.reconcile_source(SOURCE_ID).await,
        Err(ServiceError::Adapter(SourceAdapterError::Unavailable))
    ));
    assert_eq!(
        fixture
            .service
            .store()
            .item(item.item_id)
            .await
            .unwrap()
            .state,
        OccurrenceState::Completed
    );
}

#[tokio::test]
async fn source_event_diagnostics_are_bounded_and_payload_free() {
    let _database = DATABASE.lock().await;
    let fixture =
        fixture_with_source(MockSource::with_diagnostic_events(), policy(10, 1_000)).await;
    let configured_project = project(policy(10, 1_000));
    let app = router(HttpState {
        service: fixture.service.clone(),
        authenticator: Arc::new(authenticator(&configured_project)),
        project: Arc::new(configured_project),
    });
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_writer(logs.clone())
        .finish();
    async {
        assert!(fixture
            .service
            .receive_event(
                SOURCE_ID,
                EventRequest {
                    headers: Vec::new(),
                    body: b"direct-event".to_vec(),
                },
            )
            .await
            .unwrap());
        assert!(!fixture
            .service
            .receive_event(
                SOURCE_ID,
                EventRequest {
                    headers: Vec::new(),
                    body: b"direct-event".to_vec(),
                },
            )
            .await
            .unwrap());

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/events/sources/{SOURCE_ID}"))
                        .body(Body::from("http-event"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let response = app
            .oneshot(
                Request::post(format!("/events/sources/{SOURCE_ID}"))
                    .header("x-untrusted-subject", "INVALID-HEADER-CANARY")
                    .body(Body::from("INVALID-BODY-CANARY"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    .with_subscriber(subscriber)
    .await;

    let entries = logs.entries();
    for (event_id, expected_outcomes) in [
        ("diagnostic-direct", ["accepted", "duplicate"]),
        ("diagnostic-http", ["accepted", "duplicate"]),
    ] {
        for outcome in expected_outcomes {
            let matching = entries
                .iter()
                .filter(|entry| {
                    entry.pointer("/fields/message").and_then(|v| v.as_str())
                        == Some("Casework source event recorded")
                        && entry.pointer("/fields/event_id").and_then(|v| v.as_str())
                            == Some(event_id)
                        && entry.pointer("/fields/outcome").and_then(|v| v.as_str())
                            == Some(outcome)
                })
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "one {outcome} log for {event_id}: {entries:?}"
            );
            let fields = matching[0]["fields"].as_object().unwrap();
            assert_eq!(fields["source_id"], SOURCE_ID);
            assert_eq!(fields["source_revision"], 7);
            assert_eq!(fields["event_id_truncated"], false);
            assert_eq!(
                fields.keys().map(String::as_str).collect::<HashSet<_>>(),
                HashSet::from([
                    "message",
                    "source_id",
                    "event_id",
                    "event_id_truncated",
                    "source_revision",
                    "outcome",
                ])
            );
        }
    }
    let refused = entries
        .iter()
        .filter(|entry| {
            entry.pointer("/fields/message").and_then(|v| v.as_str())
                == Some("Casework source event refused")
        })
        .collect::<Vec<_>>();
    assert_eq!(refused.len(), 1);
    let refused_fields = refused[0]["fields"].as_object().unwrap();
    assert_eq!(refused_fields["source_id"], SOURCE_ID);
    assert_eq!(refused_fields["outcome"], "refused");
    assert_eq!(refused_fields["reason"], "verification");
    assert_eq!(
        refused_fields
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>(),
        HashSet::from(["message", "source_id", "outcome", "reason"])
    );
    let rendered = serde_json::to_string(&entries).unwrap();
    for canary in [
        "INVALID-HEADER-CANARY",
        "INVALID-BODY-CANARY",
        "diagnostic-subject-must-not-be-logged",
    ] {
        assert!(!rendered.contains(canary));
    }
}

async fn periodic_reconciliation_refreshes_same_revision_actionability() {
    let subject_id = Uuid::from_u128(12);
    let (source, attachment_verified) = MockSource::with_attachment_verification(subject_id);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    assert!(fixture
        .service
        .store()
        .ingest_transition(
            GENERATION,
            &TransitionHint {
                subject: subject(subject_id),
                deduplication_key: "initial-request-observation".into(),
                ordered_revision: 1,
            },
        )
        .await
        .unwrap());
    assert_eq!(fixture.service.synchronize_pending(1).await.unwrap(), 1);
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .expect("pending attachment request is locally visible");
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-attachment-request",
        )
        .await
        .unwrap();
    let (pending, _) = fixture
        .service
        .caller_item(&fixture.staff, claimed.item_id, "reader", "token")
        .await
        .unwrap();
    assert!(!pending
        .actions
        .iter()
        .any(|action| action.operation == "approve"));

    attachment_verified.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture.service.reconcile_source(SOURCE_ID).await.unwrap(),
        0
    );
    let (verified, _) = fixture
        .service
        .caller_item(&fixture.staff, claimed.item_id, "reader", "token")
        .await
        .unwrap();
    assert_eq!(verified.item_id, claimed.item_id);
    assert_eq!(verified.holder, claimed.holder);
    assert_eq!(verified.first_observed_at, claimed.first_observed_at);
    assert_eq!(verified.passive_due_at, claimed.passive_due_at);
    assert_eq!(verified.revision, claimed.revision + 1);
    assert!(verified.actions.iter().any(|action| {
        action.operation == "approve" && action.if_match == format!("\"{}\"", verified.revision)
    }));
}

#[tokio::test]
async fn terminal_attempt_replays_do_not_repeat_source_execution() {
    let _database = DATABASE.lock().await;
    let subject_id = Uuid::from_u128(10);
    let (source, prepare_calls, execute_calls) =
        MockSource::with_successful_action(subject_id, CallerRead::Visible("authorized"));
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, Some(1)).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-terminal",
        )
        .await
        .unwrap();
    let (attempt, receipt) = fixture
        .service
        .decide(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            &claimed.binding,
            "terminal-key",
            "token",
        )
        .await
        .unwrap();
    assert!(receipt.is_some());
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let by_id = fixture
        .service
        .recover(
            &fixture.staff,
            claimed.item_id,
            attempt.attempt_id,
            "reader",
            "token",
        )
        .await
        .unwrap();
    let by_key = fixture
        .service
        .recover_by_key(
            &fixture.staff,
            claimed.item_id,
            "reader",
            "terminal-key",
            "token",
        )
        .await
        .unwrap();
    assert_eq!(by_id.0, attempt);
    assert_eq!(by_key.0, attempt);
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn completed_action_binding_is_returned_and_replayable_before_reconciliation() {
    let _database = DATABASE.lock().await;
    let subject_id = Uuid::from_u128(36);
    let (source, prepare_calls, execute_calls) =
        MockSource::with_successful_binding_change(subject_id);
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, Some(1)).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-advanced-binding",
        )
        .await
        .unwrap();
    let operation = OperationName::parse("approve").expect("approve operation");

    let completed = fixture
        .service
        .decide_mutation(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            operation.clone(),
            None,
            &[],
            &claimed.binding,
            "advanced-binding-key",
            "token",
        )
        .await
        .expect("the successful action returns before reconciliation");
    let attempt = completed.attempt.expect("completed attempt is returned");
    assert_eq!(attempt.state, AttemptState::Completed);
    assert_eq!(
        attempt.receipt.as_ref().map(|receipt| &receipt.binding),
        Some(&advanced_action_binding())
    );
    assert_eq!(completed.item.state, OccurrenceState::Synchronizing);
    assert_eq!(completed.item.binding, claimed.binding);
    assert!(completed.item.actions.is_empty());
    assert!(completed.item.live_attempt.is_none());
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        fixture
            .service
            .caller_item(&fixture.staff, claimed.item_id, "reader", "token")
            .await,
        Err(ServiceError::BindingMoved)
    ));
    assert!(matches!(
        fixture
            .service
            .recover_mutation(
                &fixture.staff,
                claimed.item_id,
                attempt.attempt_id,
                "other-reader",
                "original-binding-token",
            )
            .await,
        Err(ServiceError::NotFound)
    ));
    let changed_role = ActorContext {
        role: CaseworkRole::Administrator,
        ..fixture.staff.clone()
    };
    assert!(fixture
        .service
        .decide_mutation(
            &changed_role,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            &claimed.binding,
            "advanced-binding-key",
            "original-binding-token",
        )
        .await
        .is_err());

    let repeated = fixture
        .service
        .decide_mutation(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            operation,
            None,
            &[],
            &claimed.binding,
            "advanced-binding-key",
            "token",
        )
        .await
        .expect("an idempotent retry returns the original result");
    let recovered_by_id = fixture
        .service
        .recover_mutation(
            &fixture.staff,
            claimed.item_id,
            attempt.attempt_id,
            "reader",
            "token",
        )
        .await
        .expect("the completed attempt is recoverable by id");
    let recovered_by_key = fixture
        .service
        .recover_mutation_by_key(
            &fixture.staff,
            claimed.item_id,
            "reader",
            "advanced-binding-key",
            "token",
        )
        .await
        .expect("the completed attempt is recoverable by key");
    for response in [&repeated, &recovered_by_id, &recovered_by_key] {
        assert_eq!(response.item.binding, claimed.binding);
        assert!(response.item.actions.is_empty());
        assert!(response.item.live_attempt.is_none());
        assert_eq!(response.attempt.as_ref(), Some(&attempt));
    }
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    for token in ["advanced-terminal-binding", "moved-generation-token"] {
        assert!(matches!(
            fixture
                .service
                .recover_mutation(
                    &fixture.staff,
                    claimed.item_id,
                    attempt.attempt_id,
                    "reader",
                    token,
                )
                .await,
            Err(ServiceError::BindingMoved)
        ));
    }
    assert!(matches!(
        fixture
            .service
            .recover_mutation(
                &fixture.staff,
                claimed.item_id,
                attempt.attempt_id,
                "reader",
                "concealed-token",
            )
            .await,
        Err(ServiceError::Adapter(SourceAdapterError::Concealed))
    ));
    assert!(matches!(
        fixture
            .service
            .recover_mutation(
                &fixture.staff,
                claimed.item_id,
                attempt.attempt_id,
                "reader",
                "unavailable-token",
            )
            .await,
        Err(ServiceError::Adapter(SourceAdapterError::Unavailable))
    ));
    for actor in [
        actor("other-staff", CaseworkRole::Staff),
        ActorContext {
            profile_id: "other-casework-profile".into(),
            ..fixture.staff.clone()
        },
    ] {
        assert!(fixture
            .service
            .recover_mutation(
                &actor,
                claimed.item_id,
                attempt.attempt_id,
                "reader",
                "token",
            )
            .await
            .is_err());
    }
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);
}

async fn request_correction_copy_is_persisted_then_filtered_for_the_caller() {
    let subject_id = Uuid::from_u128(11);
    let reason = "Correct the public field";
    let (source, _, execute_calls) = MockSource::with_successful_action(
        subject_id,
        CallerRead::Routing {
            reason,
            readable_fields: &["public", "nested.path"],
        },
    );
    let fixture = fixture_with_source(source, policy(10, 1_000)).await;
    add_item(&fixture.service, subject_id, Some(1)).await;
    let item = fixture
        .service
        .store()
        .inbox_candidates(&fixture.staff, 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .unwrap();
    let claimed = fixture
        .service
        .store()
        .claim(
            &fixture.staff,
            item.item_id,
            item.revision,
            "claim-correction",
        )
        .await
        .unwrap();
    fixture
        .service
        .decide(
            &fixture.staff,
            claimed.item_id,
            claimed.revision,
            "reader",
            OperationName::parse("request_correction").expect("request correction operation"),
            Some(reason),
            &["public".into(), "private".into(), "nested.path".into()],
            &claimed.binding,
            "correction-key",
            "token",
        )
        .await
        .unwrap();
    assert_eq!(execute_calls.load(Ordering::SeqCst), 1);

    let raw = fixture
        .service
        .store()
        .correction_routing_copy(claimed.item_id)
        .await
        .unwrap()
        .expect("completed correction persists routing context");
    assert_eq!(raw.reason.as_deref(), Some(reason));
    assert_eq!(raw.flagged_fields, ["public", "private", "nested.path"]);

    let (visible, _) = fixture
        .service
        .caller_item(&fixture.staff, claimed.item_id, "reader", "token")
        .await
        .unwrap();
    let filtered = visible
        .routing_copy
        .expect("caller-disclosed routing context survives filtering");
    assert_eq!(filtered.reason.as_deref(), Some(reason));
    assert_eq!(filtered.flagged_fields, ["public"]);
}

#[tokio::test]
async fn http_authentication_and_directory_authority_are_enforced() {
    let _database = DATABASE.lock().await;
    reset_database().await;
    let resolver = SecretResolver::new([SecretProvider::Environment], "/")
        .expect("environment-only secret resolver");
    let database = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{DATABASE_ENV}"),
        migration_url_ref: format!("secret:env/{DATABASE_ENV}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration = PostgresStore::connect_migration(&database, &resolver).unwrap();
    migration.migrate().await.unwrap();
    let store = PostgresStore::connect_runtime(&database, &resolver).unwrap();
    let item_subject = Uuid::from_u128(6);
    let (source, prepare_calls, execute_calls) =
        MockSource::with_successful_action(item_subject, CallerRead::Visible("authorized"));
    let project = project(policy(10, 1_000));
    let service = CaseworkService::new(
        store.clone(),
        project.clone(),
        [Arc::new(source) as Arc<dyn SourceAdapter>],
    )
    .unwrap();
    let casework_authenticator = Arc::new(authenticator(&project));
    let app = router(HttpState {
        service: service.clone(),
        authenticator: casework_authenticator,
        project: Arc::new(project.clone()),
    });

    let bootstrap = authenticated_request(
        "POST",
        "/v1/directory/bootstrap",
        &access_token("bootstrap-administrator"),
        "administrator",
        json!({
            "teamId": "team",
            "staff": [{"issuer": TOKEN_ISSUER, "subject": "staff"}],
            "supervisors": [{"issuer": TOKEN_ISSUER, "subject": "supervisor"}],
            "queueId": QUEUE
        }),
        &[
            (IF_MATCH_HEADER, "\"0\""),
            (IDEMPOTENCY_KEY_HEADER, "bootstrap"),
        ],
    );
    let response = app.clone().oneshot(bootstrap).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_body(response).await;
    assert_eq!(body["revision"], 1);
    assert_eq!(body["teams"][0]["id"], "team");

    add_item(&service, item_subject, Some(1)).await;
    let item = service
        .store()
        .inbox_candidates(&actor("staff", CaseworkRole::Staff), 1, None, None)
        .await
        .unwrap()
        .items
        .pop()
        .expect("seeded work item");
    let item_path = format!("/v1/work-items/{}", item.item_id);

    let missing_source_profile = authenticated_request(
        "GET",
        "/v1/work-items?view=my_teams",
        &access_token("staff"),
        "staff",
        json!(null),
        &[],
    );
    let response = app.clone().oneshot(missing_source_profile).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = response_body(response).await;
    assert_eq!(problem["code"], "source-profile.required");
    assert!(problem["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("Registry-Source-Profile")));

    let mut mixed_project = project.clone();
    let mut hosted_kind = standalone_decision_starter_kind();
    hosted_kind.queue = QUEUE.to_owned();
    assert!(!hosted_kind
        .deciding_profiles
        .iter()
        .any(|profile| profile == "supervisor"));
    mixed_project.hosted_kinds.push(hosted_kind);
    let mixed_service = CaseworkService::new(
        store,
        mixed_project.clone(),
        [Arc::new(MockSource::with_reads([])) as Arc<dyn SourceAdapter>],
    )
    .unwrap();
    let mixed_app = router(HttpState {
        service: mixed_service,
        authenticator: Arc::new(authenticator(&mixed_project)),
        project: Arc::new(mixed_project),
    });
    let hosted_supervisor = authenticated_request(
        "GET",
        "/v1/work-items?view=my_teams",
        &access_token("supervisor"),
        "supervisor",
        json!(null),
        &[],
    );
    let response = mixed_app.oneshot(hosted_supervisor).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response_body(response).await;
    assert_eq!(page["items"], json!([]));
    assert_eq!(page["status"], "complete");

    let next = authenticated_request(
        "GET",
        "/v1/work-items/next",
        &access_token("staff"),
        "staff",
        json!(null),
        &[(SOURCE_PROFILE_HEADER, "reader")],
    );
    let response = app.clone().oneshot(next).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response_body(response).await;
    assert_eq!(page["status"], "budget_exhausted");
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    assert!(page["nextCursor"].is_string());

    for profile in ["administrator", "supervisor"] {
        let list = authenticated_request(
            "GET",
            "/v1/work-items?view=my_teams",
            &access_token("staff"),
            profile,
            json!(null),
            &[(SOURCE_PROFILE_HEADER, "reader")],
        );
        let response = app.clone().oneshot(list).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page = response_body(response).await;
        assert_eq!(page["items"], json!([]));
        assert_eq!(page["status"], "complete");
        assert_eq!(page["servedQueues"], json!([]));
    }

    let holdings = authenticated_request(
        "GET",
        "/v1/holdings",
        &access_token("staff"),
        "supervisor",
        json!(null),
        &[(SOURCE_PROFILE_HEADER, "reader")],
    );
    let response = app.clone().oneshot(holdings).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = response_body(response).await;
    assert_eq!(page["items"], json!([]));
    assert_eq!(page["status"], "complete");

    let holdings = authenticated_request(
        "GET",
        "/v1/holdings",
        &access_token("staff"),
        "administrator",
        json!(null),
        &[(SOURCE_PROFILE_HEADER, "reader")],
    );
    assert_eq!(
        app.clone().oneshot(holdings).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let nonmember = authenticated_request(
        "GET",
        &item_path,
        &access_token("breg-reader"),
        "staff",
        json!(null),
        &[(SOURCE_PROFILE_HEADER, "reader")],
    );
    let response = app.clone().oneshot(nonmember).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let concealed = response_body(response).await.to_string();
    assert!(!concealed.contains(&item.item_id.to_string()));
    assert!(!concealed.contains(&item.subject.id));

    let service_token = source_reader_service_token();
    let service_claim = authenticated_request(
        "POST",
        &format!("{item_path}/claim"),
        &service_token,
        "staff",
        json!(null),
        &[
            (SOURCE_PROFILE_HEADER, "reader"),
            (IF_MATCH_HEADER, "\"1\""),
            (IDEMPOTENCY_KEY_HEADER, "service-claim"),
        ],
    );
    let service_claim = app.clone().oneshot(service_claim).await.unwrap();
    assert_eq!(service_claim.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_body(service_claim).await["code"],
        "profile.not-human"
    );
    let service_decision = authenticated_request(
        "POST",
        &format!("{item_path}/decisions"),
        &service_token,
        "staff",
        json!({
            "displayedBinding": binding(),
            "sourceProfileId": "reader",
            "operation": "approve"
        }),
        &[
            (SOURCE_PROFILE_HEADER, "reader"),
            (IF_MATCH_HEADER, "\"1\""),
            (IDEMPOTENCY_KEY_HEADER, "service-decision"),
        ],
    );
    let service_decision = app.clone().oneshot(service_decision).await.unwrap();
    assert_eq!(service_decision.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_body(service_decision).await["code"],
        "profile.not-human"
    );
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
    let would_be_service_actor = ActorContext {
        principal: IssuerPrincipal {
            issuer: TOKEN_ISSUER.into(),
            subject: "staff".into(),
        },
        profile_id: "staff".into(),
        role: CaseworkRole::Staff,
    };
    assert!(matches!(
        service
            .store()
            .load_prepared_attempt_by_key(&would_be_service_actor, item.item_id, "service-decision")
            .await,
        Err(StoreError::NotFound)
    ));

    for profile in ["supervisor", "administrator"] {
        let claim = authenticated_request(
            "POST",
            &format!("{item_path}/claim"),
            &access_token("staff"),
            profile,
            json!(null),
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"1\""),
                (IDEMPOTENCY_KEY_HEADER, profile),
            ],
        );
        assert_eq!(
            app.clone().oneshot(claim).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }

    let claim = authenticated_request(
        "POST",
        &format!("{item_path}/claim"),
        &access_token("staff"),
        "staff",
        json!(null),
        &[
            (SOURCE_PROFILE_HEADER, "reader"),
            (IF_MATCH_HEADER, "\"1\""),
            (IDEMPOTENCY_KEY_HEADER, "staff-claim"),
        ],
    );
    let response = app.clone().oneshot(claim).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let claimed_body = response_body(response).await;
    let actions = claimed_body["item"]["actions"]
        .as_array()
        .expect("source claim returns assembled actions");
    assert!(actions
        .iter()
        .any(|action| { action["operation"] == "release" && action["ifMatch"] == "\"2\"" }));
    assert!(actions
        .iter()
        .any(|action| action["operation"] == "approve"));
    let already_claimed = authenticated_request(
        "POST",
        &format!("{item_path}/claim"),
        &access_token("staff"),
        "staff",
        json!(null),
        &[
            (SOURCE_PROFILE_HEADER, "reader"),
            (IF_MATCH_HEADER, "\"1\""),
            (IDEMPOTENCY_KEY_HEADER, "second-staff-claim"),
        ],
    );
    let response = app.clone().oneshot(already_claimed).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(response.headers().get(ATTEMPT_REFERENCE_HEADER).is_none());
    assert_eq!(
        response_body(response).await["code"],
        "work-item.already-claimed"
    );

    for profile in ["supervisor", "administrator"] {
        let decide = authenticated_request(
            "POST",
            &format!("{item_path}/decisions"),
            &access_token("staff"),
            profile,
            json!({
                "displayedBinding": binding(),
                "sourceProfileId": "reader",
                "operation": "approve"
            }),
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"2\""),
                (IDEMPOTENCY_KEY_HEADER, profile),
            ],
        );
        assert_eq!(
            app.clone().oneshot(decide).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);

    let unsupported_reason = authenticated_request(
        "POST",
        &format!("{item_path}/decisions"),
        &access_token("staff"),
        "staff",
        json!({
            "displayedBinding": binding(),
            "sourceProfileId": "reader",
            "operation": "approve",
            "reason": "not accepted by this source operation"
        }),
        &[
            (SOURCE_PROFILE_HEADER, "reader"),
            (IF_MATCH_HEADER, "\"2\""),
            (IDEMPOTENCY_KEY_HEADER, "approve-with-reason"),
        ],
    );
    let response = app.clone().oneshot(unsupported_reason).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let problem = response_body(response).await;
    assert_eq!(problem["code"], "request.reason-unsupported");
    assert!(problem["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("reason")));
    assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
    assert_eq!(execute_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        service
            .store()
            .load_prepared_attempt_by_key(
                &would_be_service_actor,
                item.item_id,
                "approve-with-reason"
            )
            .await,
        Err(StoreError::NotFound)
    ));
}

fn authenticator(project: &CaseworkProject) -> CaseworkAuthenticator {
    let keys: JwkSet = serde_json::from_value(json!({
        "keys": [{
            "kty": "oct",
            "kid": TOKEN_KID,
            "alg": "HS256",
            "use": "sig",
            "k": TOKEN_SECRET_BASE64URL
        }]
    }))
    .unwrap();
    CaseworkAuthenticator::new(
        project,
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.into()],
            vec![Algorithm::HS256],
            vec!["at+jwt".into()],
        )
        .with_scope_claim("registry_scopes"),
        Arc::new(JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())),
        HumanIdentityConfig::default(),
    )
}

fn access_token(subject: &str) -> String {
    access_token_with_scopes(subject, &["casework"], true)
}

fn source_reader_service_token() -> String {
    access_token_with_scopes("staff", &["casework"], false)
}

fn access_token_with_scopes(subject: &str, scopes: &[&str], human: bool) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TOKEN_KID.into());
    header.typ = Some("at+jwt".into());
    encode(
        &header,
        &if human {
            json!({
                "iss": TOKEN_ISSUER,
                "aud": TOKEN_AUDIENCE,
                "sub": subject,
                "iat": now - 1,
                "exp": now + 300,
                "registry_scopes": scopes,
                "registry_actor_kind": "human"
            })
        } else {
            json!({
                "iss": TOKEN_ISSUER,
                "aud": TOKEN_AUDIENCE,
                "sub": subject,
                "iat": now - 1,
                "exp": now + 300,
                "registry_scopes": scopes
            })
        },
        &EncodingKey::from_secret(TOKEN_SECRET),
    )
    .unwrap()
}

fn authenticated_request(
    method: &str,
    uri: &str,
    token: &str,
    profile: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&body).unwrap()
    };
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(CASEWORK_PROFILE_HEADER, profile);
    if !bytes.is_empty() {
        request = request.header("content-type", "application/json");
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(bytes)).unwrap()
}

async fn response_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}
