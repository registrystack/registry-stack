//! Real PostgreSQL proofs for the review-only staffing and provider boundaries.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use registry_casework::*;
use registry_casework_core::*;
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio_postgres::NoTls;
use uuid::Uuid;

fn project_value(source: bool, routing: bool) -> Value {
    let mut value = json!({
     "apiVersion":CASEWORK_API_VERSION,"kind":CASEWORK_KIND,"project":{"id":"acceptance","version":"1"},
     "accessProfiles":[
      {"id":"staff","role":"staff","principalClaim":"sub","requiredScopes":["casework:review"]},
      {"id":"supervisor","role":"supervisor","principalClaim":"sub","requiredScopes":["casework:supervise"]},
      {"id":"administrator","role":"administrator","principalClaim":"sub","requiredScopes":["casework:admin"]},
      {"id":"producer","role":"requester","principalClaim":"sub","requiredScopes":["casework:request"]}],
     "queues":[{"id":"reviews","label":"Reviews"},{"id":"north","label":"North reviews"}],
     "teams":[{"id":"review-team","label":"Review team","serves":["reviews","north"],"memberProfiles":["staff"],"supervisorProfiles":["supervisor"]}],
     "clocks":[{"id":"deadline","type":"subject","anchor":"request-accepted-at","completeOn":"result-terminal","after":{"elapsed":"PT48H"}}],
     "reviewPolicies":[{"id":"notice-review","version":"1","purpose":"approval","context":{"mode":"submitted"},
      "stages":[{"id":"review","queue":"reviews","decidingProfiles":["staff"],"requiredApprovals":1,"excludeInitiator":true}],
      "clocks":["deadline"],"retention":{"terminalDays":30,"accountabilityDays":90},
      "outcomes":[{"id":"approved","label":"Approve","settlement":"approved","reasonRequired":false},{"id":"rejected","label":"Reject","settlement":"rejected","reasonRequired":true}],
      "displaySchema":{"type":"object","additionalProperties":false,"required":["title","region"],"properties":{"title":{"type":"string","maxLength":160},"region":{"type":"string","maxLength":20}}}}],
     "trustedProducers":[{"id":"notice-service","profile":"producer","issuer":"https://issuer.test","subject":"notice-service","trustedInitiatorIssuer":"https://issuer.test","sourceNamespaces":["notice-source"],"reviewPolicies":["notice-review"],"recoveryDays":7}]
    });
    if source {
        let bytes = registry_platform_canonical_json::canonicalize_json(
            &value["reviewPolicies"][0]["displaySchema"],
        )
        .unwrap();
        value["reviewPolicies"][0]["context"] = json!({"mode":"current-source","provider":"notice-context","contract":{"id":"notice-context-v1","revision":ContentDigest::for_bytes(b"producer-v1"),"schemaDigest":ContentDigest::for_bytes(&bytes)}});
        value["contextProviders"] = json!([{"id":"notice-context","capabilities":["human-display","service-status","routing-context","task-grant-context"],"sourceNamespace":"notice-source","deploymentRef":"notices","serviceProfiles":{"service-status":"status","routing-context":"routing","task-grant-context":"grants"}}]);
    }
    if routing {
        value["reviewPolicies"][0]["routing"] = json!([{"id":"north","because":"Route north notices locally","when":{"fields":{"region":{"equals":"north"}}},"queue":"north"}]);
    }
    value
}
fn decode(value: &Value) -> CaseworkProject {
    CaseworkProject::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn actor(subject: &str, role: CaseworkRole) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://issuer.test".into(),
            subject: subject.into(),
        },
        profile_id: match role {
            CaseworkRole::Staff => "staff",
            CaseworkRole::Supervisor => "supervisor",
            CaseworkRole::Administrator => "administrator",
            CaseworkRole::Requester => "producer",
        }
        .into(),
        role,
    }
}
#[derive(Default)]
struct ProviderState {
    hidden: Mutex<BTreeSet<String>>,
    references: Mutex<BTreeMap<String, String>>,
    routing: Mutex<Vec<ServiceContextRequest>>,
    human_reads: AtomicUsize,
    status_reads: AtomicUsize,
    unavailable: AtomicBool,
    moved: AtomicBool,
    extra_fields: AtomicBool,
}
struct SubstituteProvider(Arc<ProviderState>);
#[async_trait]
impl ReviewContextProvider for SubstituteProvider {
    fn provider_id(&self) -> &str {
        "notice-context"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
            ReviewContextCapability::RoutingContext,
            ReviewContextCapability::TaskGrantContext,
        ]
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        self.0.human_reads.fetch_add(1, Ordering::SeqCst);
        // This source accepts only the exact caller credential/profile; no service fallback.
        if request.credential.expose() != "human-source-token"
            || request.source_profile_id != "source-staff"
        {
            return Err(ReviewContextError::Denied);
        }
        if self
            .0
            .hidden
            .lock()
            .unwrap()
            .contains(&request.identity.subject.id)
        {
            return Err(ReviewContextError::Concealed);
        }
        if self.0.unavailable.load(Ordering::SeqCst) {
            return Err(ReviewContextError::Unavailable);
        }
        let mut identity = request.identity.clone();
        if self.0.moved.load(Ordering::SeqCst) {
            identity.subject.version = "successor".into();
        }
        Ok(HumanDisplayObservation {
            identity,
            reviewable: true,
            display_reference: Some(
                self.0
                    .references
                    .lock()
                    .unwrap()
                    .get(&request.identity.subject.id)
                    .cloned()
                    .unwrap_or_else(|| request.identity.subject.id.clone()),
            ),
            fields: BTreeMap::from([
                ("title".into(), json!("Private notice")),
                ("region".into(), json!("north")),
            ]),
        })
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        self.0.status_reads.fetch_add(1, Ordering::SeqCst);
        if self.0.unavailable.load(Ordering::SeqCst) {
            return Err(ReviewContextError::Unavailable);
        }
        let mut identity = identity.clone();
        if self.0.moved.load(Ordering::SeqCst) {
            identity.contract.revision = ContentDigest::for_bytes(b"changed-producer");
        }
        Ok(ServiceStatusObservation {
            identity,
            reviewable: true,
        })
    }
    async fn routing_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        assert_eq!(request.purpose, "review-task-routing");
        assert_eq!(request.fields, vec!["region"]);
        assert_eq!(request.task_revision, 1);
        self.0.routing.lock().unwrap().push(request.clone());
        let mut fields = BTreeMap::from([("region".into(), json!("north"))]);
        if self.0.extra_fields.load(Ordering::SeqCst) {
            fields.insert("unrequested-secret".into(), json!("private"));
        }
        Ok(ServiceContextObservation {
            request: request.clone(),
            reviewable: true,
            fields,
        })
    }
    async fn task_grant_context(
        &self,
        request: &ServiceContextRequest,
    ) -> Result<ServiceContextObservation, ReviewContextError> {
        assert_eq!(request.purpose, "task-grant-recheck");
        Ok(ServiceContextObservation {
            request: request.clone(),
            reviewable: true,
            fields: request
                .fields
                .iter()
                .map(|f| (f.clone(), json!("north")))
                .collect(),
        })
    }
}
struct Fixture {
    service: CaseworkService,
    store: PostgresStore,
    db: tokio_postgres::Client,
    project: CaseworkProject,
    state: Arc<ProviderState>,
    audit: AuditCapture,
}
impl Fixture {
    async fn new(value: Value) -> Self {
        let base = std::env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
            .expect("disposable review database required");
        let schema = format!("acceptance_{}", Uuid::new_v4().simple());
        let (admin, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base.contains('?') { '&' } else { '?' };
        let scoped = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let variable = format!("CASEWORK_ACCEPTANCE_{}", Uuid::new_v4().simple()).to_uppercase();
        std::env::set_var(&variable, &scoped);
        let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp").unwrap();
        let config = DatabaseConfig {
            runtime_url_ref: format!("secret:env/{variable}"),
            migration_url_ref: format!("secret:env/{variable}"),
            trusted_root_certificate_ref: None,
            test_only_plaintext: true,
        };
        let (audit, capture) = CaseworkAudit::capture();
        let migration = PostgresStore::connect_migration(&config, &secrets)
            .unwrap()
            .with_audit(audit.clone());
        migration.migrate().await.unwrap();
        let store = PostgresStore::connect_runtime(&config, &secrets)
            .unwrap()
            .with_audit(audit);
        let (db, connection) = tokio_postgres::connect(&scoped, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        db.batch_execute("INSERT INTO casework_teams(team_id,revision) VALUES('review-team',1); INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('reviews','review-team',1),('north','review-team',1); INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('review-team','https://issuer.test','a','staff'),('review-team','https://issuer.test','b','staff'),('review-team','https://issuer.test','supervisor','supervisor');").await.unwrap();
        let project = decode(&value);
        let state = Arc::new(ProviderState::default());
        let providers = if project.context_providers.is_empty() {
            vec![]
        } else {
            vec![Arc::new(SubstituteProvider(Arc::clone(&state))) as Arc<dyn ReviewContextProvider>]
        };
        let service = CaseworkService::new(store.clone(), project.clone(), providers).unwrap();
        Self {
            service,
            store,
            db,
            project,
            state,
            audit: capture,
        }
    }
    fn request(&self, id: &str) -> ReviewCreateRequest {
        ReviewCreateRequest {
            policy: self
                .project
                .compile_policy("notice-review")
                .unwrap()
                .binding(),
            subject: SubjectBinding {
                source: "notice-source".into(),
                subject_type: "notice".into(),
                id: id.into(),
                version: "1".into(),
                digest: ContentDigest::for_bytes(id.as_bytes()),
            },
            requester_reference: format!("ref-{id}"),
            initiator: Some(HumanIdentity {
                issuer: "https://issuer.test".into(),
                subject: "initiator".into(),
            }),
            context: if self.project.context_providers.is_empty() {
                ReviewContext::Submitted {
                    snapshot: json!({"title":"Private notice","region":"north"}),
                }
            } else {
                ReviewContext::CurrentSource {
                    binding: SourceContextBinding {
                        reference: format!("notices:{id}:1"),
                    },
                }
            },
            result_constraints: None,
        }
    }
    async fn create(&self, id: &str) -> ReviewRequestAccepted {
        self.service
            .create_review_request(
                &actor("notice-service", CaseworkRole::Requester),
                self.request(id),
                &format!("create-{id}"),
            )
            .await
            .unwrap()
            .accepted
    }
    async fn task(&self, request: Uuid) -> Uuid {
        self.db.query_one("SELECT task_id FROM casework_review_tasks WHERE request_id=$1 AND state IN('open','claimed') ORDER BY stage_index,slot DESC LIMIT 1",&[&request]).await.unwrap().get(0)
    }
    fn profile(&self) -> Option<&str> {
        if self.project.context_providers.is_empty() {
            None
        } else {
            Some("source-staff")
        }
    }
    async fn claim(&self, task: Uuid, who: &str) -> ReviewTask {
        self.service
            .claim_review_task(
                &actor(who, CaseworkRole::Staff),
                task,
                self.profile(),
                "human-source-token",
                1,
                &format!("claim-{who}-{task}"),
            )
            .await
            .unwrap()
    }
    async fn holders(&self) -> Vec<(Uuid, Option<String>, i64)> {
        self.db.query("SELECT task_id,holder_subject,revision FROM casework_review_tasks ORDER BY task_id",&[]).await.unwrap().into_iter().map(|r|(r.get(0),r.get(1),r.get(2))).collect()
    }
}

#[tokio::test]
async fn exact_policy_admission_and_independent_producer_authority() {
    let f = Fixture::new(project_value(false, false)).await;
    let mut request = f.request("notice");
    request.policy.digest = ContentDigest::for_bytes(b"wrong-policy");
    assert!(matches!(
        f.service
            .create_review_request(
                &actor("notice-service", CaseworkRole::Requester),
                request,
                "mismatch"
            )
            .await,
        Err(ReviewRuntimeError::PolicyMismatch)
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(matches!(
        f.service
            .create_review_request(
                &actor("a", CaseworkRole::Staff),
                f.request("notice"),
                "reviewer-create"
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    let accepted = f.create("notice").await;
    assert_eq!(accepted.policy, f.request("notice").policy);
    let recovered = f
        .service
        .create_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            f.request("notice"),
            "create-notice",
        )
        .await
        .unwrap();
    assert!(recovered.recovered);
    assert_eq!(accepted, recovered.accepted);
    assert!(matches!(
        f.service
            .review_result(
                &actor("other-producer", CaseworkRole::Requester),
                accepted.request_id
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert!(matches!(
        f.service
            .claim_review_task(
                &actor("notice-service", CaseworkRole::Requester),
                f.task(accepted.request_id).await,
                None,
                "",
                1,
                "producer-claim"
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
}
#[tokio::test]
async fn submitted_two_stage_review_pins_policy_receipts_and_terminal_feed() {
    let mut value = project_value(false, false);
    let mut second = value["reviewPolicies"][0]["stages"][0].clone();
    second["id"] = json!("independent");
    second["excludePreviousStageReviewers"] = json!(true);
    value["reviewPolicies"][0]["stages"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let f = Fixture::new(value).await;
    let accepted = f.create("two-stage").await;
    let task = f.task(accepted.request_id).await;
    let held = f.claim(task, "a").await;
    let decision = ReviewTaskDecisionRequest {
        decision: DecisionKind::Approve,
    };
    let transition = f
        .service
        .decide_review_task(
            &actor("a", CaseworkRole::Staff),
            task,
            decision.clone(),
            None,
            "",
            held.revision,
            "first-decision",
        )
        .await
        .unwrap();
    assert!(matches!(transition, ReviewTransition::StageAdvanced { .. }));
    let second = f.task(accepted.request_id).await;
    assert!(matches!(
        f.service
            .claim_review_task(
                &actor("a", CaseworkRole::Staff),
                second,
                None,
                "",
                1,
                "same-reviewer"
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    let held = f.claim(second, "b").await;
    f.service
        .decide_review_task(
            &actor("b", CaseworkRole::Staff),
            second,
            decision,
            None,
            "",
            held.revision,
            "final-decision",
        )
        .await
        .unwrap();
    let receipt = f
        .service
        .review_task(&actor("a", CaseworkRole::Staff), task, None, "")
        .await
        .unwrap()
        .decision_receipt
        .unwrap();
    assert_eq!(receipt.policy, accepted.policy);
    for table in ["casework_review_results", "casework_review_terminal_events"] {
        assert_eq!(
            f.db.query_one(
                &format!("SELECT count(*) FROM {table} WHERE request_id=$1"),
                &[&accepted.request_id]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
    }
    let feed = f
        .service
        .review_result_feed(&actor("notice-service", CaseworkRole::Requester), None, 100)
        .await
        .unwrap();
    assert_eq!(feed.items.len(), 1);
    assert_eq!(feed.items[0].request_id, accepted.request_id);
    let ReviewResultRead::Available(result) = f
        .service
        .review_result(
            &actor("notice-service", CaseworkRole::Requester),
            accepted.request_id,
        )
        .await
        .unwrap()
    else {
        panic!("terminal result")
    };
    assert_eq!(result.policy, accepted.policy);
    let published = serde_json::to_string(&f.audit.entries()).unwrap();
    assert!(!published.contains("Private notice"));
    assert!(!published.contains("human-source-token"));
}
#[tokio::test]
async fn reference_selection_conceals_before_sort_and_rejects_stale_continuation() {
    let f = Fixture::new(project_value(true, false)).await;
    for id in ["z", "a", "hidden"] {
        f.create(id).await;
    }
    f.state.hidden.lock().unwrap().insert("hidden".into());
    let query = ReviewStaffingQuery {
        sort: ReviewTaskSort::Reference,
        limit: Some(1),
        ..Default::default()
    };
    let first = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            query.clone(),
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].subject.id, "a");
    let cursor = first.next_cursor.unwrap();
    let hidden = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            ReviewStaffingQuery {
                reference: Some("hidden".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(hidden.items.is_empty());
    f.state
        .references
        .lock()
        .unwrap()
        .insert("z".into(), "0".into());
    assert!(matches!(
        f.service
            .review_staffing_tasks(
                &actor("a", CaseworkRole::Staff),
                Some("source-staff"),
                "human-source-token",
                ReviewStaffingQuery {
                    cursor: Some(cursor),
                    ..query
                }
            )
            .await,
        Err(ReviewRuntimeError::ResultExpired)
    ));
    let denied = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "service-token",
            Default::default(),
        )
        .await
        .unwrap();
    assert!(denied.items.is_empty());
    let request = f.request("z");
    let exact = ReviewStaffingQuery {
        subject_source: Some(request.subject.source),
        subject_type: Some(request.subject.subject_type),
        subject_id: Some(request.subject.id),
        subject_version: Some(request.subject.version),
        subject_digest: Some(request.subject.digest),
        ..Default::default()
    };
    let exact = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            exact,
        )
        .await
        .unwrap();
    assert_eq!(exact.items.len(), 1);
}
#[tokio::test]
async fn current_source_routing_is_purpose_bound_once_and_never_persists_fields() {
    let mut value = project_value(true, true);
    value["reviewPolicies"][0]["stages"][0]["requiredApprovals"] = json!(2);
    let f = Fixture::new(value).await;
    let accepted = f.create("routed").await;
    let calls = f.state.routing.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0].task_id, calls[1].task_id);
    assert!(calls
        .iter()
        .all(|c| c.policy == accepted.policy && c.request_id == accepted.request_id));
    let rows =
        f.db.query(
            "SELECT queue_id FROM casework_review_tasks WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .unwrap();
    assert!(rows.iter().all(|r| r.get::<_, String>(0) == "north"));
    let context: Value =
        f.db.query_one(
            "SELECT context FROM casework_review_requests WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(context.get("snapshot").is_none());
    assert!(!serde_json::to_string(&context)
        .unwrap()
        .contains("Private notice"));
    f.service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(f.state.routing.lock().unwrap().len(), 2);
    let f = Fixture::new(project_value(true, true)).await;
    f.state.extra_fields.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.service
            .create_review_request(
                &actor("notice-service", CaseworkRole::Requester),
                f.request("widened"),
                "widened"
            )
            .await,
        Err(ReviewRuntimeError::SourceInvalid)
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
#[tokio::test]
async fn caseload_preview_apply_is_atomic_revision_fenced_and_recoverable() {
    let f = Fixture::new(project_value(false, false)).await;
    for id in ["one", "two"] {
        let accepted = f.create(id).await;
        f.claim(f.task(accepted.request_id).await, "a").await;
    }
    let supervisor = actor("supervisor", CaseworkRole::Supervisor);
    let movement = ReviewCaseloadMoveRequest {
        from: actor("a", CaseworkRole::Staff).principal,
        to: actor("b", CaseworkRole::Staff).principal,
        queue: None,
        reason: "Balance today's caseload".into(),
    };
    let preview = f
        .service
        .preview_review_caseload(&supervisor, None, "", movement.clone())
        .await
        .unwrap();
    assert_eq!(preview.tasks.len(), 2);
    f.db.execute(
        "UPDATE casework_review_tasks SET revision=revision+1 WHERE task_id=$1",
        &[&preview.tasks[0].task_id],
    )
    .await
    .unwrap();
    let before = f.holders().await;
    assert!(matches!(
        f.service
            .apply_review_caseload(
                &supervisor,
                None,
                "",
                ReviewCaseloadApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await,
        Err(ReviewRuntimeError::RevisionConflict)
    ));
    assert_eq!(before, f.holders().await);
    let preview = f
        .service
        .preview_review_caseload(&supervisor, None, "", movement)
        .await
        .unwrap();
    let apply = ReviewCaseloadApplyRequest {
        preview_id: preview.preview_id,
    };
    let result = f
        .service
        .apply_review_caseload(&supervisor, None, "", apply.clone())
        .await
        .unwrap();
    assert_eq!(result.moved.len(), 2);
    assert!(f
        .holders()
        .await
        .iter()
        .all(|(_, holder, _)| holder.as_deref() == Some("b")));
    assert_eq!(
        f.service
            .apply_review_caseload(&supervisor, None, "", apply)
            .await
            .unwrap(),
        result
    );
}
#[tokio::test]
async fn source_visibility_and_directory_authority_are_both_live_at_caseload_apply() {
    let f = Fixture::new(project_value(true, false)).await;
    let accepted = f.create("live").await;
    f.claim(f.task(accepted.request_id).await, "a").await;
    let supervisor = actor("supervisor", CaseworkRole::Supervisor);
    let movement = ReviewCaseloadMoveRequest {
        from: actor("a", CaseworkRole::Staff).principal,
        to: actor("b", CaseworkRole::Staff).principal,
        queue: None,
        reason: "Cover absence".into(),
    };
    let preview = f
        .service
        .preview_review_caseload(
            &supervisor,
            Some("source-staff"),
            "human-source-token",
            movement,
        )
        .await
        .unwrap();
    let before = f.holders().await;
    f.state.hidden.lock().unwrap().insert("live".into());
    assert!(matches!(
        f.service
            .apply_review_caseload(
                &supervisor,
                Some("source-staff"),
                "human-source-token",
                ReviewCaseloadApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await,
        Err(ReviewRuntimeError::NotFound)
    ));
    assert_eq!(before, f.holders().await);
    f.state.hidden.lock().unwrap().clear();
    f.db.execute(
        "DELETE FROM casework_memberships WHERE subject='supervisor'",
        &[],
    )
    .await
    .unwrap();
    assert!(matches!(
        f.service
            .apply_review_caseload(
                &supervisor,
                Some("source-staff"),
                "human-source-token",
                ReviewCaseloadApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(before, f.holders().await);
}
#[tokio::test]
async fn provider_failure_refuses_affected_work_while_submitted_review_remains_usable() {
    let f = Fixture::new(project_value(true, false)).await;
    let accepted = f.create("source").await;
    let task = f.task(accepted.request_id).await;
    f.state.unavailable.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.service
            .claim_review_task(
                &actor("a", CaseworkRole::Staff),
                task,
                Some("source-staff"),
                "human-source-token",
                1,
                "unavailable"
            )
            .await,
        Err(ReviewRuntimeError::SourceUnavailable)
    ));
    let submitted = decode(&project_value(false, false));
    let service = CaseworkService::new(
        f.store.clone(),
        submitted.clone(),
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    let mut request = f.request("standalone");
    request.policy = submitted.compile_policy("notice-review").unwrap().binding();
    request.context = ReviewContext::Submitted {
        snapshot: json!({"title":"Private notice","region":"north"}),
    };
    let accepted = service
        .create_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            request,
            "standalone",
        )
        .await
        .unwrap()
        .accepted;
    service
        .claim_review_task(
            &actor("a", CaseworkRole::Staff),
            f.task(accepted.request_id).await,
            None,
            "",
            1,
            "standalone-claim",
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn due_order_holdings_and_pinned_subject_clock_recompute() {
    let f = Fixture::new(project_value(false, false)).await;
    let first = f.create("later").await;
    let second = f.create("earlier").await;
    let first_task = f.task(first.request_id).await;
    let second_task = f.task(second.request_id).await;
    let earlier = Utc::now() + TimeDelta::hours(1);
    f.db.execute(
        "UPDATE casework_review_tasks SET deadline_at=$2 WHERE task_id=$1",
        &[&second_task, &earlier],
    )
    .await
    .unwrap();
    let tasks = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            None,
            "",
            Default::default(),
        )
        .await
        .unwrap();
    assert_eq!(tasks.items[0].task_id, second_task);
    f.claim(first_task, "a").await;
    let holdings = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            None,
            "",
            ReviewStaffingQuery {
                ownership: Some(ReviewTaskOwnership::AssignedToMe),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(holdings.items.len(), 1);
    assert_eq!(holdings.items[0].task_id, first_task);
    let mut active = f.project.clone();
    let ClockPolicy::Subject { after, .. } = &mut active.clocks[0] else {
        panic!()
    };
    after.elapsed = "PT1H".into();
    let changed = CaseworkService::new(
        f.store.clone(),
        active,
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    let admin = actor("admin", CaseworkRole::Administrator);
    let preview = changed
        .preview_review_clock_recompute(
            &admin,
            None,
            "",
            ReviewClockRecomputeRequest {
                task_ids: vec![first_task],
            },
        )
        .await
        .unwrap();
    let deadline = preview.tasks[0].deadline_at.unwrap();
    assert!(deadline > Utc::now() + TimeDelta::hours(47));
    let applied = changed
        .apply_review_clock_recompute(
            &admin,
            None,
            "",
            ReviewClockRecomputeApplyRequest {
                preview_id: preview.preview_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(applied.tasks[0].deadline_at, Some(deadline));
    assert_eq!(applied.tasks[0].revision, 3);
}
#[tokio::test]
async fn activation_refuses_rebinding_a_producer_with_open_requests() {
    let f = Fixture::new(project_value(false, false)).await;
    f.create("open").await;
    let mut active = f.project.clone();
    active.trusted_producers[0].subject = "replacement".into();
    let conflicts = stranded_pinned_work(&f.store, &active, &[]).await.unwrap();
    assert!(!conflicts.is_empty());
    assert!(conflicts
        .iter()
        .any(|c| c.reason.contains("bound producer")));
}

#[tokio::test]
async fn live_read_budget_requires_narrowing_and_exact_subject_narrows_before_scan() {
    let mut value = project_value(true, false);
    value["inbox"] = json!({"defaultPageSize":1,"maximumSourceReads":1,"maximumCandidateScan":2});
    let f = Fixture::new(value).await;
    for id in ["one", "two", "three"] {
        f.create(id).await;
    }
    assert!(matches!(
        f.service
            .review_staffing_tasks(
                &actor("a", CaseworkRole::Staff),
                Some("source-staff"),
                "human-source-token",
                Default::default()
            )
            .await,
        Err(ReviewRuntimeError::QueryTooBroad)
    ));
    let subject = f.request("three").subject;
    let query = ReviewStaffingQuery {
        subject_source: Some(subject.source),
        subject_type: Some(subject.subject_type),
        subject_id: Some(subject.id),
        subject_version: Some(subject.version),
        subject_digest: Some(subject.digest),
        ..Default::default()
    };
    let page = f
        .service
        .review_staffing_tasks(
            &actor("a", CaseworkRole::Staff),
            Some("source-staff"),
            "human-source-token",
            query,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].subject.id, "three");
}
#[tokio::test]
async fn admission_namespace_cannot_substitute_the_pinned_provider_namespace() {
    let mut value = project_value(true, false);
    value["trustedProducers"][0]["sourceNamespaces"] = json!(["notice-source", "other-source"]);
    let f = Fixture::new(value).await;
    let mut request = f.request("subject");
    request.subject.source = "other-source".into();
    assert!(matches!(
        f.service
            .create_review_request(
                &actor("notice-service", CaseworkRole::Requester),
                request,
                "wrong-namespace"
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(
        f.db.query_one("SELECT count(*) FROM casework_review_requests", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
#[tokio::test]
async fn submitted_routing_needs_no_provider_and_request_clocks_do_not_share_round_budget() {
    let f = Fixture::new(project_value(false, true)).await;
    let first = f.create("notice").await;
    let task = f.task(first.request_id).await;
    assert_eq!(
        f.db.query_one(
            "SELECT queue_id FROM casework_review_tasks WHERE task_id=$1",
            &[&task]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "north"
    );
    assert!(f.state.routing.lock().unwrap().is_empty());
    let held = f.claim(task, "a").await;
    f.service
        .decide_review_task(
            &actor("a", CaseworkRole::Staff),
            task,
            ReviewTaskDecisionRequest {
                decision: DecisionKind::Reject {
                    outcome: "rejected".into(),
                    reason: Some("Withdraw the original notice".into()),
                    result: None,
                },
            },
            None,
            "",
            held.revision,
            "reject",
        )
        .await
        .unwrap();
    let mut request = f.request("notice");
    request.subject.version = "2".into();
    request.subject.digest = ContentDigest::for_bytes(b"notice-v2");
    let second = f
        .service
        .create_review_request(
            &actor("notice-service", CaseworkRole::Requester),
            request,
            "round-two",
        )
        .await
        .unwrap()
        .accepted;
    let rows=f.db.query("SELECT request_id,state,correlation_key FROM casework_review_clock_occurrences ORDER BY created_at",&[]).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, Uuid>(0), first.request_id);
    assert_eq!(rows[0].get::<_, String>(1), "completed");
    assert_eq!(rows[1].get::<_, Uuid>(0), second.request_id);
    assert_eq!(rows[1].get::<_, String>(1), "running");
    assert_ne!(rows[0].get::<_, String>(2), rows[1].get::<_, String>(2));
}
#[tokio::test]
async fn clock_recompute_uses_pinned_calendar_and_fences_changed_holiday_inputs() {
    let mut value = project_value(false, false);
    value["calendars"] = json!([{"id":"office","timezone":"UTC","workingWeekdays":["monday","tuesday","wednesday","thursday","friday","saturday","sunday"],"holidaySet":"office-holidays"}]);
    value["clocks"] = json!([{"id":"deadline","type":"activity","anchor":"stage-entered-at","calendar":"office","after":{"workingDays":1},"dueTime":"17:00","reminders":[],"steps":[]}]);
    let f = Fixture::new(value).await;
    let admin = actor("admin", CaseworkRole::Administrator);
    let holiday = HolidaySetDocument {
        holiday_set: "office-holidays".into(),
        revision: 1,
        dates: vec![],
    };
    f.service
        .create_holiday_revision(&admin, &holiday, "holiday-1")
        .await
        .unwrap();
    let accepted = f.create("calendar").await;
    let task = f.task(accepted.request_id).await;
    let original: chrono::DateTime<Utc> =
        f.db.query_one(
            "SELECT deadline_at FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap()
        .get(0);
    let preview = f
        .service
        .preview_review_clock_recompute(
            &admin,
            None,
            "",
            ReviewClockRecomputeRequest {
                task_ids: vec![task],
            },
        )
        .await
        .unwrap();
    let holiday = HolidaySetDocument {
        holiday_set: holiday.holiday_set,
        revision: 2,
        dates: vec![original.format("%Y-%m-%d").to_string()],
    };
    f.service
        .create_holiday_revision(&admin, &holiday, "holiday-2")
        .await
        .unwrap();
    assert!(matches!(
        f.service
            .apply_review_clock_recompute(
                &admin,
                None,
                "",
                ReviewClockRecomputeApplyRequest {
                    preview_id: preview.preview_id
                }
            )
            .await,
        Err(ReviewRuntimeError::RevisionConflict)
    ));
    assert_eq!(
        f.db.query_one(
            "SELECT revision FROM casework_review_tasks WHERE task_id=$1",
            &[&task]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let mut active = f.project.clone();
    let ClockPolicy::Activity { after, .. } = &mut active.clocks[0] else {
        panic!()
    };
    after.working_days = 9;
    let service = CaseworkService::new(
        f.store.clone(),
        active,
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    let preview = service
        .preview_review_clock_recompute(
            &admin,
            None,
            "",
            ReviewClockRecomputeRequest {
                task_ids: vec![task],
            },
        )
        .await
        .unwrap();
    let expected = original + TimeDelta::days(1);
    assert_eq!(preview.tasks[0].deadline_at, Some(expected));
    let result = service
        .apply_review_clock_recompute(
            &admin,
            None,
            "",
            ReviewClockRecomputeApplyRequest {
                preview_id: preview.preview_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.tasks[0].deadline_at, Some(expected));
    assert!(matches!(
        service
            .preview_review_clock_recompute(
                &actor("a", CaseworkRole::Staff),
                None,
                "",
                ReviewClockRecomputeRequest {
                    task_ids: vec![task]
                }
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
}

#[path = "support/independent_staffing_activation.rs"]
mod independent_staffing_activation;

#[path = "support/commit_audit_regressions.rs"]
mod commit_audit_regressions;
#[path = "support/creation_audit_regressions.rs"]
mod creation_audit_regressions;
#[path = "support/maintenance_audit_regressions.rs"]
mod maintenance_audit_regressions;

#[path = "support/clock_progress_regressions.rs"]
mod clock_progress_regressions;

#[path = "support/authority_closure_regressions.rs"]
mod authority_closure_regressions;
