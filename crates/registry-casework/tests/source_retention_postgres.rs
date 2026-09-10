// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
    IssuerPrincipal, OccurrenceKind, OccurrenceState, OperationName, PrepareActionRequest,
    PreparedSourceAttempt, QueuePolicy, RecoveryEvidence, SourceAdapter, SourceAdapterError,
    SourceBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy, SourceRetentionSelector,
    SubjectRef, TransitionHint, CASEWORK_API_VERSION, CASEWORK_KIND, CASEWORK_PROFILE_HEADER,
    IDEMPOTENCY_KEY_HEADER, IF_MATCH_HEADER, SOURCE_PROFILE_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifierConfig};
use serde_json::{json, Value};
use tokio_postgres::NoTls;
use tower::ServiceExt;
use uuid::Uuid;

const DATABASE_ENV: &str = "CASEWORK_SOURCE_RETENTION_TEST_DATABASE_URL";
const SOURCE_ID: &str = "registry";
const REQUEST_KIND: &str = "correction";
const QUEUE: &str = "default";
const GENERATION: &str = "generation-1";
const TOKEN_ISSUER: &str = "https://issuer.example";
const TOKEN_AUDIENCE: &str = "registry-casework";
const TOKEN_KID: &str = "casework-retention-key";
const TOKEN_SECRET: &[u8] = b"01234567890123456789012345678901";
const TOKEN_SECRET_BASE64URL: &str = "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE";
const CANARY: &str = "ERASED-SOURCE-PAYLOAD-CANARY";

struct SourceFixture {
    reads: Arc<AtomicUsize>,
}

#[async_trait]
impl SourceAdapter for SourceFixture {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    fn binding_generation(&self) -> &str {
        GENERATION
    }

    async fn verify_transition(
        &self,
        _request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Ok(observation(subject.id.clone(), 1))
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Ok(ActiveSubjectsPage {
            subjects: Vec::new(),
            next_cursor: None,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: binding(1),
            disclosed: BTreeMap::from([("summary".to_owned(), json!(CANARY))]),
            permitted_operations: vec![
                OperationName::parse("request_correction").expect("operation")
            ],
        })
    }

    async fn prepare_action(
        &self,
        request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Ok(PreparedSourceAttempt {
            source_binding: request.displayed_binding.clone(),
            recovery_evidence: RecoveryEvidence::new(CANARY.as_bytes().to_vec())?,
        })
    }

    async fn execute_prepared(
        &self,
        request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Ok(SourceReceipt {
            source_revision: "2".to_owned(),
            resulting_state: "needs_changes".to_owned(),
            binding: request.prepared.source_binding.clone(),
            actor_reference: Some("opaque-reviewer-7".to_owned()),
            metadata: BTreeMap::from([("nativeReceipt".to_owned(), CANARY.to_owned())]),
        })
    }
}

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: TOKEN_ISSUER.to_owned(),
            subject: subject.to_owned(),
        },
        profile_id: profile_id.to_owned(),
        role,
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec!["casework".to_owned()],
        role,
        kinds: Vec::new(),
    }
}

fn project() -> CaseworkProject {
    CaseworkProject {
        api_version: CASEWORK_API_VERSION.to_owned(),
        kind: CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "source-retention-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
        ],
        queues: vec![QueuePolicy {
            id: QUEUE.to_owned(),
            label: "Default".to_owned(),
        }],
        sources: vec![SourcePolicy {
            id: SOURCE_ID.to_owned(),
            adapter: "test".to_owned(),
            description: "Retention source fixture".to_owned(),
            requests: vec![SourceRequestPolicy {
                entity: REQUEST_KIND.to_owned(),
                queue: QUEUE.to_owned(),
                projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }],
        hosted_kinds: Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

fn binding(revision: i64) -> SourceBinding {
    SourceBinding {
        source_revision: revision.to_string(),
        version: "1".to_owned(),
        integrity: None,
        generation: GENERATION.to_owned(),
    }
}

fn observation(id: String, revision: i64) -> AuthoritativeObservation {
    AuthoritativeObservation {
        submitted_at: None,
        stage_entered_at: None,
        review_timing: None,
        routing_context: None,
        subject: SubjectRef {
            source_id: SOURCE_ID.to_owned(),
            kind: REQUEST_KIND.to_owned(),
            id,
        },
        occurrence_key: "review:1".to_owned(),
        ordered_revision: revision,
        binding: binding(revision),
        representation_etag: format!("\"request-{revision}\""),
        occurrence_kind: OccurrenceKind::Review,
        stage: Some("review".to_owned()),
        state: OccurrenceState::Open,
        remaining_actions: vec![OperationName::parse("request_correction").expect("operation")],
    }
}

#[tokio::test]
async fn source_erasure_scrubs_payloads_fences_rehydration_and_preserves_expired_replay() {
    let database_url = env::var(DATABASE_ENV).expect("dedicated retention database URL");
    let (database, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect dedicated retention database");
    tokio::spawn(async move { connection.await.expect("database connection") });
    database
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .await
        .expect("reset dedicated retention database");

    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("environment resolver");
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{DATABASE_ENV}"),
        migration_url_ref: format!("secret:env/{DATABASE_ENV}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&config, &secrets)
        .expect("migration store")
        .migrate()
        .await
        .expect("migrations");
    let store = PostgresStore::connect_runtime(&config, &secrets).expect("runtime store");
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let staff = actor("staff", CaseworkRole::Staff, "staff");
    let outsider = actor("outsider", CaseworkRole::Staff, "staff");
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: Vec::new(),
                queue_id: QUEUE.to_owned(),
            },
            "bootstrap",
        )
        .await
        .expect("directory");

    let reads = Arc::new(AtomicUsize::new(0));
    let configured_project = project();
    let service = CaseworkService::new(
        store.clone(),
        configured_project.clone(),
        [Arc::new(SourceFixture {
            reads: Arc::clone(&reads),
        }) as Arc<dyn SourceAdapter>],
    )
    .expect("service");
    let request_id = Uuid::new_v4().to_string();
    let source_observation = observation(request_id.clone(), 1);
    let item = store
        .apply_observation(&source_observation, QUEUE, None)
        .await
        .expect("observation")
        .expect("work item");
    let claimed = store
        .claim(&staff, item.item_id, 1, "claim-key")
        .await
        .expect("claim");
    let drafted = store
        .save_draft(
            &staff,
            item.item_id,
            claimed.revision,
            &claimed.binding,
            CANARY,
            &["field-a".to_owned()],
            "draft-key",
        )
        .await
        .expect("draft");
    let current = store.item(item.item_id).await.expect("current item");
    let decision = service
        .decide(
            &staff,
            item.item_id,
            current.revision,
            "reader",
            OperationName::parse("request_correction").expect("operation"),
            Some(CANARY),
            &["field-a".to_owned()],
            &current.binding,
            "decision-key",
            "source-token",
        )
        .await
        .expect("completed decision");
    assert!(decision.1.is_some());

    let selected_clock = Uuid::new_v4();
    let other_clock = Uuid::new_v4();
    let preview_id = Uuid::new_v4();
    let other_request_id = Uuid::new_v4().to_string();
    database
        .execute(
            "INSERT INTO casework_subjects(source_id,subject_kind,subject_id,binding_generation,wanted_revision,applied_revision,representation_etag,active,sync_pending) VALUES($1,$2,$3,$4,1,1,'\"other-1\"',true,false)",
            &[&SOURCE_ID, &REQUEST_KIND, &other_request_id, &GENERATION],
        )
        .await
        .expect("other subject");
    for (clock_id, subject_id, item_id) in [
        (selected_clock, request_id.as_str(), Some(item.item_id)),
        (other_clock, other_request_id.as_str(), None),
    ] {
        database.execute("INSERT INTO casework_clock_occurrences(clock_occurrence_id,source_id,subject_kind,subject_id,clock_id,scope,scope_key,item_id,state,policy_digest,current_calculation_generation,recompute_generation,source_binding_generation,source_revision,source_etag,next_action_at,lease_token,lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,'review-clock','subject','subject',$5,'running','sha256:clock',1,0,$6,1,'\"clock-1\"',now(),$7,now()+interval '5 minutes',now(),now())", &[&clock_id,&SOURCE_ID,&REQUEST_KIND,&subject_id,&item_id,&GENERATION,&Uuid::new_v4()]).await.expect("clock occurrence");
        database.execute("INSERT INTO casework_clock_calculations(clock_occurrence_id,generation,recompute_generation,policy_digest,policy,calendar,holiday_document,source_timing,anchor_at,started_at,due_at,at_risk_at,reminders,steps,completed_at,created_at) VALUES($1,1,0,'sha256:clock','{}','{}','{}',$2,now(),now(),now()+interval '1 day',NULL,'[]','[]',NULL,now())", &[&clock_id,&json!({"reason":CANARY})]).await.expect("clock calculation");
        database.execute("INSERT INTO casework_clock_recompute_previews(preview_id,clock_occurrence_id,actor_issuer,actor_subject,profile_id,expected_calculation_generation,expected_source_revision,expected_source_etag,proposed_policy_digest,proposed_policy,proposed_calendar,proposed_holiday_document,proposed_due_at,proposed_at_risk_at,proposed_reminders,proposed_steps,expires_at) VALUES($1,$2,$3,$4,$5,1,1,'\"clock-1\"','sha256:next','{}','{}','{}',now()+interval '2 days',NULL,'[]','[]',now()+interval '15 minutes')", &[&preview_id,&clock_id,&administrator.principal.issuer,&administrator.principal.subject,&administrator.profile_id]).await.expect("clock preview");
    }
    database.execute("INSERT INTO casework_idempotency(issuer,subject,profile_id,operation,resource,idempotency_key,request_hash,response,created_at) VALUES($1,$2,$3,'clock.recompute.apply',$4,'clock-apply','sha256:preview',$5,now())", &[&administrator.principal.issuer,&administrator.principal.subject,&administrator.profile_id,&preview_id.to_string(),&json!({"occurrences":[selected_clock,other_clock],"canary":CANARY})]).await.expect("clock replay");
    database.execute("INSERT INTO casework_cursors(cursor_id,issuer,subject,casework_profile_id,source_profile_id,context,last_passive_due_at,last_item_id,expires_at) VALUES($1,$2,$3,$4,'reader','retention-cursor',now(),$5,now()+interval '15 minutes')", &[&Uuid::new_v4(),&staff.principal.issuer,&staff.principal.subject,&staff.profile_id,&item.item_id]).await.expect("source cursor");
    database.execute("INSERT INTO casework_assignment_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_item_id,expires_at) VALUES($1,$2,$3,$4,'sha256:cursor',$5,now()+interval '15 minutes')", &[&Uuid::new_v4(),&staff.principal.issuer,&staff.principal.subject,&staff.profile_id,&item.item_id]).await.expect("assignment cursor");
    let history_event: Uuid = database
        .query_one(
            "SELECT event_id FROM casework_history WHERE item_id=$1 ORDER BY occurred_at LIMIT 1",
            &[&item.item_id],
        )
        .await
        .expect("history event")
        .get(0);
    database
        .execute(
            "UPDATE casework_audit_outbox SET audit_record=$2 WHERE event_id=$1",
            &[
                &history_event,
                &json!({"detail":CANARY,"reason":CANARY,"sourceReceipt":CANARY}),
            ],
        )
        .await
        .expect("audit canary");

    let selector = SourceRetentionSelector {
        source_id: SOURCE_ID.to_owned(),
        request_kind: REQUEST_KIND.to_owned(),
        request_id: request_id.clone(),
    };
    let preview = store
        .preview_source_retention(&selector)
        .await
        .expect("retention preview");
    assert!(!preview.applied);
    assert_eq!(preview.items, 1);
    assert_eq!(preview.drafts, 1);
    assert_eq!(preview.correction_contexts, 1);
    assert_eq!(preview.clock_occurrences, 1);
    assert_eq!(preview.clock_previews, 2);
    assert!(preview.idempotency_responses >= 3);
    let report = store
        .erase_source_retention(&selector)
        .await
        .expect("retention apply");
    assert!(report.applied);
    assert_eq!(report.clock_previews, 2);

    assert!(matches!(
        store.item(item.item_id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.history(&staff, item.item_id, 100).await,
        Err(StoreError::NotFound)
    ));
    assert!(store.events(None, 100).await.expect("events").is_empty());
    assert!(store
        .apply_observation(&observation(request_id.clone(), 2), QUEUE, None)
        .await
        .expect("erased observation fence")
        .is_none());
    assert!(!store
        .ingest_transition(
            GENERATION,
            &TransitionHint {
                subject: source_observation.subject.clone(),
                deduplication_key: "post-erasure-event".to_owned(),
                ordered_revision: 3,
            },
        )
        .await
        .expect("erased event fence"));
    assert!(store
        .claim_sync_batch(100, 30)
        .await
        .expect("sync batch")
        .into_iter()
        .all(|subject| subject.id != request_id));

    let payload_snapshot: Value = database
        .query_one(
            "SELECT jsonb_build_object('drafts',(SELECT count(*) FROM casework_drafts WHERE item_id=$1),'correction',(SELECT count(*) FROM casework_correction_context WHERE item_id=$1),'attempt',(SELECT jsonb_build_object('reason',decision_reason,'fields',flagged_fields,'binding',displayed_binding,'evidence',encode(recovery_evidence,'hex'),'metadata',receipt->'metadata') FROM casework_attempts WHERE item_id=$1),'history',(SELECT jsonb_agg(detail) FROM casework_history WHERE item_id=$1),'events',(SELECT jsonb_agg(detail) FROM casework_events WHERE item_id=$1),'responses',(SELECT jsonb_agg(response) FROM casework_idempotency WHERE resource=$2),'clockTiming',(SELECT source_timing FROM casework_clock_calculations WHERE clock_occurrence_id=$3),'previewRows',(SELECT count(*) FROM casework_clock_recompute_previews WHERE preview_id=$4))",
            &[&item.item_id, &item.item_id.to_string(), &selected_clock, &preview_id],
        )
        .await
        .expect("scrubbed snapshot")
        .get(0);
    let encoded = serde_json::to_string(&payload_snapshot).expect("snapshot JSON");
    assert!(!encoded.contains(CANARY));
    assert_eq!(payload_snapshot["drafts"], 0);
    assert_eq!(payload_snapshot["correction"], 0);
    assert_eq!(payload_snapshot["attempt"]["reason"], Value::Null);
    assert_eq!(payload_snapshot["attempt"]["fields"], json!([]));
    assert_eq!(payload_snapshot["attempt"]["binding"], Value::Null);
    assert_eq!(payload_snapshot["attempt"]["evidence"], Value::Null);
    assert_eq!(payload_snapshot["attempt"]["metadata"], json!({}));
    assert_eq!(payload_snapshot["clockTiming"], Value::Null);
    assert_eq!(payload_snapshot["previewRows"], 0);
    let retained_links = database
        .query_one(
            "SELECT (SELECT count(*) FROM casework_cursors WHERE last_item_id=$1),(SELECT count(*) FROM casework_assignment_cursors WHERE last_item_id=$1),(SELECT count(*) FROM casework_idempotency WHERE operation='clock.recompute.apply' AND resource=$2 AND response IS NOT NULL)",
            &[&item.item_id, &preview_id.to_string()],
        )
        .await
        .expect("retained link counts");
    assert_eq!(retained_links.get::<_, i64>(0), 0);
    assert_eq!(retained_links.get::<_, i64>(1), 0);
    assert_eq!(retained_links.get::<_, i64>(2), 0);
    let audit_text: String = database
        .query_one(
            "SELECT COALESCE(string_agg(audit_record::text,''),'') FROM casework_audit_outbox",
            &[],
        )
        .await
        .expect("audit records")
        .get(0);
    assert!(!audit_text.contains(CANARY));
    assert!(audit_text.contains("casework.source_retention_erased"));

    let restarted = PostgresStore::connect_runtime(&config, &secrets).expect("restarted store");
    assert!(matches!(
        restarted.item(item.item_id).await,
        Err(StoreError::NotFound)
    ));
    assert!(restarted
        .apply_observation(&observation(request_id.clone(), 4), QUEUE, None)
        .await
        .expect("restart fence")
        .is_none());
    assert!(matches!(
        service
            .preflight_source_claim(&staff, item.item_id, 1, "claim-key")
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(service
        .preflight_source_claim(&outsider, item.item_id, 1, "claim-key")
        .await
        .is_ok());
    let reads_before_replay = reads.load(Ordering::SeqCst);
    assert!(matches!(
        service
            .decide(
                &staff,
                item.item_id,
                current.revision,
                "reader",
                OperationName::parse("request_correction").expect("operation"),
                Some(CANARY),
                &["field-a".to_owned()],
                &current.binding,
                "decision-key",
                "source-token",
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_replay);

    let app = router(HttpState {
        service: service.clone(),
        authenticator: Arc::new(authenticator(&configured_project)),
        project: Arc::new(configured_project),
    });
    let path = format!("/v1/work-items/{}/claim", item.item_id);
    let exact = app
        .clone()
        .oneshot(authenticated_request(
            &path,
            &access_token("staff", true),
            "staff",
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"1\""),
                (IDEMPOTENCY_KEY_HEADER, "claim-key"),
            ],
        ))
        .await
        .expect("exact replay response");
    assert_eq!(exact.status(), StatusCode::GONE);
    assert_eq!(response_json(exact).await["code"], "idempotency.expired");
    let concealed = app
        .clone()
        .oneshot(authenticated_request(
            &path,
            &access_token("outsider", true),
            "staff",
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"1\""),
                (IDEMPOTENCY_KEY_HEADER, "claim-key"),
            ],
        ))
        .await
        .expect("concealed replay response");
    assert_eq!(concealed.status(), StatusCode::NOT_FOUND);
    let service_credential = app
        .clone()
        .oneshot(authenticated_request(
            &path,
            &access_token("staff", false),
            "staff",
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"1\""),
                (IDEMPOTENCY_KEY_HEADER, "claim-key"),
            ],
        ))
        .await
        .expect("service credential response");
    assert_eq!(service_credential.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(service_credential).await["code"],
        "profile.not-human"
    );
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_replay);

    database
        .execute(
            "DELETE FROM casework_memberships WHERE issuer=$1 AND subject=$2 AND membership_kind='staff'",
            &[&staff.principal.issuer, &staff.principal.subject],
        )
        .await
        .expect("revoke original staff membership");
    assert!(service
        .preflight_source_claim(&staff, item.item_id, 1, "claim-key")
        .await
        .is_ok());
    let revoked = app
        .clone()
        .oneshot(authenticated_request(
            &path,
            &access_token("staff", true),
            "staff",
            &[
                (SOURCE_PROFILE_HEADER, "reader"),
                (IF_MATCH_HEADER, "\"1\""),
                (IDEMPOTENCY_KEY_HEADER, "claim-key"),
            ],
        ))
        .await
        .expect("revoked replay response");
    assert_eq!(revoked.status(), StatusCode::NOT_FOUND);
    assert_eq!(reads.load(Ordering::SeqCst), reads_before_replay);
    database
        .execute(
            "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('team',$1,$2,'staff')",
            &[&staff.principal.issuer, &staff.principal.subject],
        )
        .await
        .expect("restore staff membership for live-attempt proof");

    let blocked_id = Uuid::new_v4().to_string();
    let blocked_item = store
        .apply_observation(&observation(blocked_id.clone(), 1), QUEUE, None)
        .await
        .expect("blocked observation")
        .expect("blocked item");
    let blocked_claim = store
        .claim(&staff, blocked_item.item_id, 1, "blocked-claim")
        .await
        .expect("blocked claim");
    store
        .reserve_attempt(
            &staff,
            blocked_item.item_id,
            blocked_claim.revision,
            "reader",
            OperationName::parse("request_correction").expect("operation"),
            Some("pending payload"),
            &[],
            "pending-key",
            "sha256:pending",
            &PreparedSourceAttempt {
                source_binding: blocked_claim.binding,
                recovery_evidence: RecoveryEvidence::new(vec![1]).expect("evidence"),
            },
        )
        .await
        .expect("pending attempt");
    let blocked = store
        .erase_source_retention(&SourceRetentionSelector {
            source_id: SOURCE_ID.to_owned(),
            request_kind: REQUEST_KIND.to_owned(),
            request_id: blocked_id,
        })
        .await;
    assert!(matches!(blocked, Err(StoreError::AttemptPending)));
    assert!(store.item(blocked_item.item_id).await.is_ok());
    assert_eq!(drafted.reason, CANARY);
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
    .expect("JWK set");
    CaseworkAuthenticator::new(
        project,
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::HS256],
            vec!["at+jwt".to_owned()],
        )
        .with_scope_claim("registry_scopes"),
        Arc::new(JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())),
        HumanIdentityConfig::default(),
    )
}

fn access_token(subject: &str, human: bool) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(TOKEN_KID.to_owned());
    header.typ = Some("at+jwt".to_owned());
    let mut claims = json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": subject,
        "iat": now - 1,
        "exp": now + 300,
        "registry_scopes": ["casework"]
    });
    if human {
        claims["registry_actor_kind"] = json!("human");
    }
    encode(&header, &claims, &EncodingKey::from_secret(TOKEN_SECRET)).expect("access token")
}

fn authenticated_request(
    path: &str,
    token: &str,
    profile: &str,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header(CASEWORK_PROFILE_HEADER, profile);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::empty()).expect("request")
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response bytes"),
    )
    .expect("problem JSON")
}
