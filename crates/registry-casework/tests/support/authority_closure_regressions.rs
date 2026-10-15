use super::*;

async fn assign(
    service: &CaseworkService,
    task: Uuid,
    subject: &str,
    key: &str,
) -> Result<ReviewTask, ReviewRuntimeError> {
    service
        .assign_review_task(
            &actor("supervisor", CaseworkRole::Supervisor),
            task,
            None,
            "",
            1,
            AssignmentRequest {
                assignee: actor(subject, CaseworkRole::Staff).principal,
                reason: None,
            },
            key,
        )
        .await
}

#[tokio::test]
async fn absence_reconciliation_requires_audit_and_recovers_without_phantom_changes() {
    let f = Fixture::new(project_value(false, false)).await;
    let accepted = f.create("absence-audit").await;
    let task = f.task(accepted.request_id).await;
    assign(&f.service, task, "a", "assign").await.unwrap();
    f.db.execute("INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) VALUES($1,'https://issuer.test','a',now()-interval '1 hour',now()+interval '1 hour','https://issuer.test','b',1)",&[&Uuid::new_v4()]).await.unwrap();
    let before = f.holders().await;
    f.audit.refuse_after(f.audit.entries().len());
    // A background admission checks writer readiness. An actual rejected
    // write first makes this a stopped destination, rather than a failure
    // injected only at the later response publication.
    assert!(matches!(
        f.service
            .create_review_request(
                &actor("notice-service", CaseworkRole::Requester),
                f.request("stop-probe"),
                "stop-probe"
            )
            .await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert!(matches!(
        f.service.reconcile_review_absences(10).await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    assert_eq!(f.holders().await, before);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_history WHERE kind='task-absence-reconciled'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let (audit, capture) = CaseworkAudit::capture();
    let service = CaseworkService::new(
        f.store.clone().with_audit(audit),
        f.project.clone(),
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    assert_eq!(service.reconcile_review_absences(10).await.unwrap(), 1);
    let row =
        f.db.query_one(
            "SELECT holder_subject FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "b");
    let entries = capture.entries();
    assert_eq!(capture.responses("task-absence-reconciled").len(), 1);
    assert_eq!(service.reconcile_review_absences(10).await.unwrap(), 0);
    assert_eq!(capture.entries(), entries);
    let text = serde_json::to_string(&entries).unwrap();
    assert!(!text.contains("https://issuer.test"));
    assert!(!text.contains(&task.to_string()));
    assert!(!text.contains("Private notice"));
}

struct PlainProvider(Arc<ProviderState>);
#[async_trait]
impl ReviewContextProvider for PlainProvider {
    fn provider_id(&self) -> &str {
        "notice-context"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &[
            ReviewContextCapability::HumanDisplay,
            ReviewContextCapability::ServiceStatus,
        ]
    }
    async fn human_display(
        &self,
        request: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        SubstituteProvider(self.0.clone())
            .human_display(request)
            .await
    }
    async fn service_status(
        &self,
        identity: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        SubstituteProvider(self.0.clone())
            .service_status(identity)
            .await
    }
}

#[tokio::test]
async fn accepted_plain_policy_does_not_pin_another_policys_optional_provider_capabilities() {
    let mut value = project_value(true, false);
    let mut routed = value["reviewPolicies"][0].clone();
    routed["id"] = json!("routed-review");
    routed["routing"] = json!([{"id":"north","because":"Route north notices","when":{"fields":{"region":{"equals":"north"}}},"queue":"north"}]);
    value["reviewPolicies"].as_array_mut().unwrap().push(routed);
    value["trustedProducers"]["notice-service"]["reviewPolicies"] =
        json!(["notice-review", "routed-review"]);
    let f = Fixture::new(value.clone()).await;
    f.create("plain").await;
    // Remove the drained routing policy while a plain review remains open.
    value["reviewPolicies"].as_array_mut().unwrap().pop();
    value["trustedProducers"]["notice-service"]["reviewPolicies"] = json!(["notice-review"]);
    let provider = PlainProvider(f.state.clone());
    let declared_project = decode(&value);
    assert!(CaseworkService::new(
        f.store.clone(),
        declared_project,
        [Arc::new(PlainProvider(f.state.clone())) as Arc<dyn ReviewContextProvider>]
    )
    .is_ok());
    value["contextProviders"][0]["capabilities"] = json!(["human-display", "service-status"]);
    value["contextProviders"][0]["serviceProfiles"] = json!({"service-status":"status"});
    let project = decode(&value);
    project.check().unwrap();
    let candidate = ActivationCandidate {
        database_id: "authority-closure-tests",
        package_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        project: &project,
        providers: &[&provider],
    };
    let plan = f.store.plan_activation(&candidate).await.unwrap();
    assert!(plan.refusals.is_empty(), "{:?}", plan.refusals);
    let pinned = f.project.compile_policy("notice-review").unwrap();
    assert_eq!(
        pinned
            .dependencies
            .context_provider
            .unwrap()
            .capabilities
            .len(),
        2
    );
    value["contextProviders"][0]["serviceProfiles"]["service-status"] = json!("replacement-status");
    let changed = decode(&value);
    let candidate = ActivationCandidate {
        project: &changed,
        ..candidate
    };
    assert!(f
        .store
        .plan_activation(&candidate)
        .await
        .unwrap()
        .refusals
        .iter()
        .any(|r| r.code == "casework.activation.stranded-work"));
}

#[tokio::test]
async fn assignment_roles_stay_pinned_and_activation_refuses_changed_deciding_authority() {
    let f = Fixture::new(project_value(false, false)).await;
    let accepted = f.create("role-pinned").await;
    let task = f.task(accepted.request_id).await;
    let mut value = project_value(false, false);
    value["accessProfiles"].as_object_mut().unwrap().insert(
        "spare-staff".into(),
        json!({"principalClaim":"sub","requiredScopes":["casework:spare-staff"],"role":"staff"}),
    );
    value["accessProfiles"]["staff"]["role"] = json!("supervisor");
    value["teams"]["review-team"]["memberProfiles"] = json!(["spare-staff"]);
    value["teams"]["review-team"]["supervisorProfiles"] = json!(["supervisor", "staff"]);
    let changed = decode(&value);
    changed.check().unwrap();
    let service = CaseworkService::new(
        f.store.clone(),
        changed.clone(),
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    let before = f.holders().await;
    assert!(matches!(
        assign(&service, task, "supervisor", "wrong-role").await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(f.holders().await, before);
    let candidate = ActivationCandidate {
        database_id: "authority-closure-tests",
        package_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        project: &changed,
        providers: &[],
    };
    assert!(f
        .store
        .plan_activation(&candidate)
        .await
        .unwrap()
        .refusals
        .iter()
        .any(|r| r.code == "casework.activation.stranded-work"));
    assign(&service, task, "a", "pinned-role").await.unwrap();
}

#[tokio::test]
async fn absence_response_failure_withholds_success_and_retry_preserves_exactly_once_change() {
    let f = Fixture::new(project_value(false, false)).await;
    let accepted = f.create("absence-response").await;
    let task = f.task(accepted.request_id).await;
    assign(&f.service, task, "a", "assign").await.unwrap();
    f.db.execute("INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) VALUES($1,'https://issuer.test','a',now()-interval '1 hour',now()+interval '1 hour','https://issuer.test','b',1)", &[&Uuid::new_v4()]).await.unwrap();
    // Ready at admission, the destination fails when this background change
    // publishes its response. The committed change must not become success.
    let prior_entries = f.audit.entries();
    f.audit.refuse_after(prior_entries.len());
    assert!(matches!(
        f.service.reconcile_review_absences(10).await,
        Err(ReviewRuntimeError::Store(StoreError::AuditUnavailable))
    ));
    let after = f.holders().await;
    assert_eq!(after, vec![(task, Some("b".to_owned()), 3)]);
    assert_eq!(f.audit.entries(), prior_entries);
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_history WHERE kind='task-absence-reconciled'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let (audit, capture) = CaseworkAudit::capture();
    let recovered = CaseworkService::new(
        f.store.clone().with_audit(audit),
        f.project.clone(),
        Vec::<Arc<dyn ReviewContextProvider>>::new(),
    )
    .unwrap();
    assert_eq!(recovered.reconcile_review_absences(10).await.unwrap(), 0);
    assert_eq!(f.holders().await, after);
    assert!(capture.entries().is_empty());
    assert_eq!(
        f.db.query_one(
            "SELECT count(*) FROM casework_review_history WHERE kind='task-absence-reconciled'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
}
