// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    AccessProfile, ActiveSubjectsPage, ActorContext, AuthoritativeObservation,
    BootstrapDirectoryRequest, CallerSubjectView, CaseworkIdentity, CaseworkProject, CaseworkRole,
    DiscoveryCursor, EphemeralCredential, EventRequest, ExecutePreparedRequest, InboxPolicy,
    IssuerPrincipal, OccurrenceKind, OccurrenceState, OperationName, PageStatus,
    PrepareActionRequest, PreparedSourceAttempt, QueuePolicy, RecoveryEvidence, SourceAdapter,
    SourceAdapterError, SourceBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy,
    SubjectRef, TransitionHint, ATTEMPT_REFERENCE_HEADER, CASEWORK_API_VERSION, CASEWORK_KIND,
    CASEWORK_PROFILE_HEADER, IDEMPOTENCY_KEY_HEADER, IF_MATCH_HEADER, SOURCE_PROFILE_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde_json::json;
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

struct MockSource {
    reads: HashMap<String, CallerRead>,
    prepare_calls: Arc<AtomicUsize>,
    terminal_read: Option<String>,
    discovery_unavailable: Arc<AtomicBool>,
    discovery_pages: Option<(Uuid, Uuid)>,
    open_reads: HashSet<String>,
    attachment_verification: Option<(String, Arc<AtomicBool>)>,
    verify_diagnostic_events: bool,
    execute_calls: Arc<AtomicUsize>,
    execute_succeeds: bool,
    definitive_refusal_after: Option<usize>,
    approve_reads: HashSet<String>,
}

impl MockSource {
    fn with_reads(reads: impl IntoIterator<Item = (Uuid, CallerRead)>) -> Self {
        Self {
            reads: reads
                .into_iter()
                .map(|(id, read)| (id.to_string(), read))
                .collect(),
            prepare_calls: Arc::new(AtomicUsize::new(0)),
            terminal_read: None,
            discovery_unavailable: Arc::new(AtomicBool::new(false)),
            discovery_pages: None,
            open_reads: HashSet::new(),
            attachment_verification: None,
            verify_diagnostic_events: false,
            execute_calls: Arc::new(AtomicUsize::new(0)),
            execute_succeeds: false,
            definitive_refusal_after: None,
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

    fn with_recovery_definitive_refusal(id: Uuid, read: CallerRead) -> (Self, Arc<AtomicUsize>) {
        let mut source = Self::with_reads([(id, read)]);
        source.definitive_refusal_after = Some(1);
        source.approve_reads.insert(id.to_string());
        let execute_calls = Arc::clone(&source.execute_calls);
        (source, execute_calls)
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
        GENERATION
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
        if self.discovery_unavailable.load(Ordering::SeqCst) {
            Err(SourceAdapterError::Unavailable)
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
        let credential = credential.expose();
        if credential == "concealed-token" {
            return Err(SourceAdapterError::Concealed);
        }
        if credential == "moved-generation-token" {
            let mut view = Self::visible(subject, "moved-generation");
            view.binding.generation = "generation-2".into();
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
        if self
            .definitive_refusal_after
            .is_some_and(|threshold| call_index >= threshold)
        {
            return Err(SourceAdapterError::DefinitiveRefusal);
        }
        if !self.execute_succeeds {
            return Err(SourceAdapterError::Invalid);
        }
        Ok(SourceReceipt {
            source_revision: "2".into(),
            resulting_state: "needs_changes".into(),
            binding: request.prepared.source_binding.clone(),
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
    Fixture {
        service,
        staff,
        supervisor,
        outsider,
    }
}

fn project(inbox: InboxPolicy) -> CaseworkProject {
    CaseworkProject {
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

async fn add_item(service: &CaseworkService, id: Uuid, passive_target_seconds: Option<i64>) {
    service
        .store()
        .apply_observation(
            &AuthoritativeObservation {
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
        .unwrap();
}

async fn complete_item(service: &CaseworkService, id: Uuid) {
    let mut completed_binding = binding();
    completed_binding.source_revision = "2".into();
    service
        .store()
        .apply_observation(
            &AuthoritativeObservation {
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
    zero_local_candidates_distinguish_empty_source_from_outage().await;
    warm_empty_source_status_does_not_mask_a_later_outage().await;
    incomplete_multipage_discovery_stays_incomplete_across_requests().await;
    sparse_disclosure_and_cursor_preserve_unvisited_candidates().await;
    source_outage_is_distinct_from_empty_inbox_and_holdings().await;
    current_directory_controls_queue_visibility().await;
    source_deadline_is_hard_and_retryable().await;
    local_terminal_repair_survives_discovery_outage().await;
    source_event_diagnostics_are_bounded_and_payload_free().await;
    periodic_reconciliation_refreshes_same_revision_actionability().await;
    request_correction_copy_is_persisted_then_filtered_for_the_caller().await;
    terminal_attempt_replays_do_not_repeat_source_execution().await;
    definitive_refusal_during_recovery_releases_the_attempt_fence().await;
    inbox_views_filter_before_candidate_pagination().await;
    recovery_problem_discloses_only_the_entitled_original_attempt().await;
    caller_owned_live_attempt_survives_a_fresh_session_without_cross_actor_disclosure().await;
    http_authentication_and_directory_authority_are_enforced().await;
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
                Err(ServiceError::Adapter(SourceAdapterError::DefinitiveRefusal))
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

async fn caller_owned_live_attempt_survives_a_fresh_session_without_cross_actor_disclosure() {
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
            "list:Mine:",
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
            "token",
            registry_casework_core::InboxView::CompletedByMe,
            1,
            "list:CompletedByMe:",
            None,
        )
        .await
        .unwrap();
    assert_eq!(completed.items.len(), 1);
    assert_eq!(completed.items[0].item_id, claimed.item_id);
}

async fn recovery_problem_discloses_only_the_entitled_original_attempt() {
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

async fn zero_local_candidates_distinguish_empty_source_from_outage() {
    let empty = fixture([], policy(10, 1_000)).await;
    let page = empty
        .service
        .inbox(&empty.staff, "reader", "token", 10, "inbox", None)
        .await
        .unwrap();
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::Complete);

    let outage =
        fixture_with_source(MockSource::with_unavailable_discovery(), policy(10, 1_000)).await;
    let page = outage
        .service
        .inbox(&outage.staff, "reader", "token", 10, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 10, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 10, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", None)
        .await
        .unwrap();
    assert!(first_probe.items.is_empty());
    assert_eq!(first_probe.status, PageStatus::BudgetExhausted);
    assert!(first_probe.next_cursor.is_some());
    assert_eq!(fixture.service.synchronize_pending(100).await.unwrap(), 1);

    let concealed_first = fixture
        .service
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", None)
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
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", Some(cursor))
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
        .inbox(&fixture.staff, "reader", "token", 1, "inbox", None)
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_millis(500));
    assert_eq!(page.status, PageStatus::SourceUnavailable);
    assert!(page.items.is_empty());
    assert!(page.next_cursor.is_some());
}

async fn source_outage_is_distinct_from_empty_inbox_and_holdings() {
    let unavailable = Uuid::from_u128(4);
    let empty = fixture([], policy(10, 1_000)).await;
    let inbox = empty
        .service
        .inbox(&empty.staff, "reader", "token", 10, "inbox", None)
        .await
        .unwrap();
    assert!(inbox.items.is_empty());
    assert_eq!(inbox.status, PageStatus::Complete);
    let holdings = empty
        .service
        .caller_visible_holdings(&empty.supervisor, "reader", "token", None)
        .await
        .unwrap();
    assert!(holdings.items.is_empty());
    assert_eq!(holdings.status, PageStatus::Complete);

    let outage = fixture([(unavailable, CallerRead::Unavailable)], policy(10, 1_000)).await;
    add_item(&outage.service, unavailable, Some(1)).await;
    let inbox = outage
        .service
        .inbox(&outage.staff, "reader", "token", 10, "inbox", None)
        .await
        .unwrap();
    assert!(inbox.items.is_empty());
    assert_eq!(inbox.status, PageStatus::SourceUnavailable);
    let holdings = outage
        .service
        .caller_visible_holdings(&outage.supervisor, "reader", "token", None)
        .await
        .unwrap();
    assert!(holdings.items.is_empty());
    assert_eq!(holdings.status, PageStatus::SourceUnavailable);
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
        .inbox(&fixture.staff, "reader", "token", 10, "inbox", None)
        .await
        .unwrap();
    assert_eq!(member.items.len(), 1);
    let outsider = fixture
        .service
        .inbox(&fixture.outsider, "reader", "token", 10, "inbox", None)
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

async fn source_event_diagnostics_are_bounded_and_payload_free() {
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

async fn terminal_attempt_replays_do_not_repeat_source_execution() {
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

async fn http_authentication_and_directory_authority_are_enforced() {
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
        store,
        project.clone(),
        [Arc::new(source) as Arc<dyn SourceAdapter>],
    )
    .unwrap();
    let authenticator = Arc::new(authenticator(&project));
    let app = router(HttpState {
        service: service.clone(),
        authenticator,
        project: Arc::new(project),
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
    assert_eq!(
        app.clone().oneshot(claim).await.unwrap().status(),
        StatusCode::OK
    );
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
