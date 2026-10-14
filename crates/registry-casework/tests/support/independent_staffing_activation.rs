//! Focused regressions for retained activation dependencies and exact staffing targets.
use super::*;

fn movement(target: &str, role: CaseworkRole) -> ReviewCaseloadMoveRequest {
    ReviewCaseloadMoveRequest {
        from: actor("a", CaseworkRole::Staff).principal,
        to: actor(target, role).principal,
        queue: None,
        reason: "Balance the review queue".into(),
    }
}

#[tokio::test]
async fn caseload_target_membership_must_match_the_pinned_deciding_profiles() {
    let f = Fixture::new(project_value(false, false)).await;
    let request = f.create("role-bound").await;
    f.claim(f.task(request.request_id).await, "a").await;
    let before = f.holders().await;
    assert!(matches!(
        f.service
            .preview_review_caseload(
                &actor("supervisor", CaseworkRole::Supervisor),
                None,
                "",
                movement("supervisor", CaseworkRole::Supervisor),
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(before, f.holders().await);

    // A later package cannot reinterpret the accepted stage's membership roles.
    let mut changed = project_value(false, false);
    changed["reviewPolicies"][0]["stages"][0]["decidingProfiles"] = json!(["staff", "supervisor"]);
    let service = CaseworkService::new(f.store.clone(), decode(&changed), []).unwrap();
    assert!(matches!(
        service
            .preview_review_caseload(
                &actor("supervisor", CaseworkRole::Supervisor),
                None,
                "",
                movement("supervisor", CaseworkRole::Supervisor),
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));

    // Explicit supervisor eligibility is supported for newly admitted work.
    let allowed = Fixture::new(changed).await;
    let request = allowed.create("supervisor-stage").await;
    allowed
        .claim(allowed.task(request.request_id).await, "a")
        .await;
    let preview = allowed
        .service
        .preview_review_caseload(
            &actor("supervisor", CaseworkRole::Supervisor),
            None,
            "",
            movement("supervisor", CaseworkRole::Supervisor),
        )
        .await
        .unwrap();
    allowed
        .service
        .apply_review_caseload(
            &actor("supervisor", CaseworkRole::Supervisor),
            None,
            "",
            ReviewCaseloadApplyRequest {
                preview_id: preview.preview_id,
            },
        )
        .await
        .unwrap();
    assert_eq!(allowed.holders().await[0].1.as_deref(), Some("supervisor"));
}

#[tokio::test]
async fn caseload_refuses_active_absence_and_rechecks_scheduled_absence_at_apply() {
    let f = Fixture::new(project_value(false, false)).await;
    for id in ["absence-one", "absence-two"] {
        let request = f.create(id).await;
        f.claim(f.task(request.request_id).await, "a").await;
    }
    let supervisor = actor("supervisor", CaseworkRole::Supervisor);
    let before = f.holders().await;
    let id = Uuid::new_v4();
    f.db.execute("INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) VALUES($1,'https://issuer.test','b',now()-interval '1 hour',now()+interval '1 hour','https://issuer.test','a',1)", &[&id]).await.unwrap();
    assert!(matches!(
        f.service
            .preview_review_caseload(&supervisor, None, "", movement("b", CaseworkRole::Staff))
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(before, f.holders().await);

    // Publish the scheduled absence before preview. Its start passes without
    // changing Directory revision, so the apply check must use the current time.
    let starts = Utc::now() + TimeDelta::seconds(2);
    f.db.execute(
        "UPDATE casework_absences SET starts_at=$2 WHERE absence_id=$1",
        &[&id, &starts],
    )
    .await
    .unwrap();
    let preview = f
        .service
        .preview_review_caseload(&supervisor, None, "", movement("b", CaseworkRole::Staff))
        .await
        .unwrap();
    let delay = (starts - Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(delay + std::time::Duration::from_millis(10)).await;
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
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(before, f.holders().await);
}

struct CapabilitiesProvider(Vec<ReviewContextCapability>);
#[async_trait]
impl ReviewContextProvider for CapabilitiesProvider {
    fn provider_id(&self) -> &str {
        "notice-context"
    }
    fn capabilities(&self) -> &[ReviewContextCapability] {
        &self.0
    }
    async fn human_display(
        &self,
        _: HumanDisplayRequest<'_>,
    ) -> Result<HumanDisplayObservation, ReviewContextError> {
        Err(ReviewContextError::Unavailable)
    }
    async fn service_status(
        &self,
        _: &ReviewContextIdentity,
    ) -> Result<ServiceStatusObservation, ReviewContextError> {
        Err(ReviewContextError::Unavailable)
    }
}

async fn activation_plan(
    f: &Fixture,
    value: &Value,
    provider: &dyn ReviewContextProvider,
) -> ActivationPlan {
    let project = decode(value);
    let providers = [provider];
    f.store
        .plan_activation(&ActivationCandidate {
            database_id: "independent-review-tests",
            package_digest: &format!("sha256:{}", "a".repeat(64)),
            project: &project,
            providers: &providers,
        })
        .await
        .unwrap()
}

async fn assert_activation_refused(
    f: &Fixture,
    value: &Value,
    provider: &dyn ReviewContextProvider,
) {
    let project = decode(value);
    let providers = [provider];
    let candidate = ActivationCandidate {
        database_id: "independent-review-tests",
        package_digest: &format!("sha256:{}", "a".repeat(64)),
        project: &project,
        providers: &providers,
    };
    let plan = f.store.plan_activation(&candidate).await.unwrap();
    assert!(
        plan.refusals
            .iter()
            .any(|r| r.code == "casework.activation.stranded-work"),
        "{:?}",
        plan.refusals
    );
    let runtime_user: String =
        f.db.query_one("SELECT current_user::text", &[])
            .await
            .unwrap()
            .get(0);
    let before: i64 =
        f.db.query_one("SELECT count(*) FROM casework_activations", &[])
            .await
            .unwrap()
            .get(0);
    assert!(matches!(
        f.store.apply_activation(&runtime_user, &candidate, &ApplyRequest::default()).await,
        Err(ActivationError::Refused(refusals)) if refusals.iter().any(|r| r.code == "casework.activation.stranded-work")
    ));
    let after: i64 =
        f.db.query_one("SELECT count(*) FROM casework_activations", &[])
            .await
            .unwrap()
            .get(0);
    assert_eq!(before, after);
}

#[tokio::test]
async fn activation_preserves_pinned_provider_namespace_profiles_binding_and_capabilities() {
    let mut value = project_value(true, true);
    value["reviewPolicies"][0]["stages"].as_array_mut().unwrap().push(json!({"id":"second-review","queue":"reviews","decidingProfiles":["staff"],"requiredApprovals":1,"excludeInitiator":true,"excludePreviousStageReviewers":true}));
    let f = Fixture::new(value.clone()).await;
    f.create("provider-pinned").await;
    let provider = SubstituteProvider(Arc::clone(&f.state));

    let mut presentation = value.clone();
    presentation["contextProviders"][0]["description"] = json!("A clearer provider description");
    presentation["queues"][0]["label"] = json!("Review notices");
    presentation["reviewPolicies"][0]["outcomes"][0]["label"] = json!("Accept notice");
    assert!(activation_plan(&f, &presentation, &provider)
        .await
        .refusals
        .is_empty());

    let mut candidates = Vec::new();
    let mut namespace = value.clone();
    namespace["contextProviders"][0]["sourceNamespace"] = json!("replacement-source");
    namespace["trustedProducers"][0]["sourceNamespaces"] =
        json!(["notice-source", "replacement-source"]);
    candidates.push(namespace);
    let mut binding = value.clone();
    binding["contextProviders"][0]["deploymentRef"] = json!("replacement-notices");
    candidates.push(binding);
    let mut profiles = value.clone();
    profiles["contextProviders"][0]["serviceProfiles"]["routing-context"] =
        json!("replacement-routing");
    candidates.push(profiles);
    let mut capabilities = value.clone();
    capabilities["reviewPolicies"][0]
        .as_object_mut()
        .unwrap()
        .remove("routing");
    capabilities["contextProviders"][0]["capabilities"] =
        json!(["human-display", "service-status", "task-grant-context"]);
    capabilities["contextProviders"][0]["serviceProfiles"]
        .as_object_mut()
        .unwrap()
        .remove("routing-context");
    candidates.push(capabilities);
    for candidate in candidates {
        assert_activation_refused(&f, &candidate, &provider).await;
    }
    // A provider can also lose a capability without changing its declaration.
    let narrowed = CapabilitiesProvider(vec![
        ReviewContextCapability::HumanDisplay,
        ReviewContextCapability::ServiceStatus,
    ]);
    assert_activation_refused(&f, &value, &narrowed).await;
}

#[tokio::test]
async fn activation_preserves_pinned_clock_step_destination_queues() {
    let mut value = project_value(false, false);
    value["calendars"] = json!([{"id":"workdays","timezone":"UTC","workingWeekdays":["monday","tuesday","wednesday","thursday","friday"],"holidaySet":"holidays"}]);
    value["clocks"] = json!([{"id":"deadline","type":"activity","anchor":"stage-entered-at","calendar":"workdays","after":{"workingDays":1},"dueTime":"17:00","steps":[{"id":"escalate","because":"Deadline reached","at":"due","action":{"reassign":{"queue":"north"}}}]}]);
    let f = Fixture::new(value.clone()).await;
    f.create("clock-pinned").await;
    let mut changed = value;
    changed["queues"]
        .as_array_mut()
        .unwrap()
        .retain(|q| q["id"] != "north");
    changed["teams"][0]["serves"] = json!(["reviews"]);
    changed["reviewPolicies"][0]["clocks"] = json!([]);
    changed["clocks"] = json!([]);
    let provider = CapabilitiesProvider(Vec::new());
    assert_activation_refused(&f, &changed, &provider).await;
}
